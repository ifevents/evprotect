import { context, AbortController, ALPNProtocol } from '@adobe/fetch'
import { WebSocket } from 'ws'
import createDebugger from 'debug'

const debug = createDebugger('ifevents/evprotect')

const DEFAULT_OPTIONS = {
  timeout: 5000,
}

const { fetch } = context({
  alpnProtocols: [ALPNProtocol.ALPN_HTTP2],
  rejectUnauthorized: false,
  userAgent: 'ifevents/evprotect',
})

const validateOptions = options => {
  if (!options.domain || typeof options.domain !== 'string') {
    debug('options.domain required (string).')
    return false
  }
  if (!options.username || typeof options.username !== 'string') {
    debug('options.username required (string).')
    return false
  }

  if (!options.password || typeof options.password !== 'string') {
    debug('options.password required (string).')
    return false
  }

  // check the rest (defaults) for type and constraints

  debug('options have been validated.')
  return true
}

const apiRequest = (options, path, inParams = {}) => {
  let abort = null
  let timeout = null

  const params = Object.assign({}, inParams)
  const uri = `https://${options.domain}${path}`

  if (!params.signal) {
    debug('No abort timer. Creating a new one,')
    abort = new AbortController()
    params.signal = abort.signal
    timeout = setTimeout(() => abort.abort(), options.timeout)
  }

  const clearAbortTimer = result => {
    debug('Clearing abort timer.')
    if (timeout) clearTimeout(timeout)
    return result
  }

  // we are rejecting with the request object so calling functions can
  // inspect it and throw an Error object that makes sense in context
  const rejectIfNotOk = request => {
    debug('Checking HTTP response.')
    return request.ok ? request : Promise.reject(request)
  }

  return fetch(uri, params)
    .then(clearAbortTimer)
    .then(rejectIfNotOk)
}

const apiLogin = options => {
  const params = {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: options.username, password: options.password }),
    method: 'POST',
  }

  const captureToken = request => {
    const cookie = request.headers.get('set-cookie')
    options.token = cookie.split(';')[0].split('=')[1]

    return request;
  }

  const captureCSRFToken = request => {
    const csrf =
      request.headers.get('x-updated-csrf-token') ||
      request.headers.get('x-csrf-token')

    if (csrf) {
      debug('CSRF Token:', csrf)
      options.csrf = csrf
    }

    return request
  }

  return apiRequest(options, '/api/auth/login', params)
    .then(captureToken)
    .then(captureCSRFToken)
    .then(result => result.json())
}

const apiBootstrap = options => {
  const params = {
    headers: {
      'cookie': `TOKEN=${options.token}`,
    },
    method: 'GET',
  }

  if (options.csrf) {
    params.headers['x-csrf-token'] = options.csrf
  }

  return apiRequest(options, '/proxy/protect/api/bootstrap', params)
    .then(result => result.json())
    .then(result => {
      options.lastUpdateId = result.lastUpdateId
      return result
    })
}

const generateWebSocketUri = (domain, lastUpdateId) => (
  `https://${domain}/proxy/protect/ws/updates?lastUpdateId=${lastUpdateId}`
)

const apiWebSocket = (options, callback) => {
  const uri = generateWebSocketUri(options.domain, options.lastUpdateId)

  options.ws = new WebSocket(uri, {
    rejectUnauthorized: false,
    headers: { 'cookie': `TOKEN = ${options.token}` },
  })

  options.ws.on('message', packet => {
    // calculate the offset of secons packet
    const offset = packet.readUInt32BE(4) + 8
    const header = JSON.parse(packet.slice(8, packet.readUInt32BE(4) + 8))
    options.lastUpdateId = header.newUpdateId

    const data = JSON.parse(packet.slice(offset + 8).toString())
    debug('Packet received:', `${header.action}(${header.modelKey})`)
    return callback('websocket', { header, data })
  })

  options.ws.on('error', err => console.log(err))
}

export default function evprotect(inOptions, inCallback) {
  // detach inOptions from the calling context and apply defaults
  const options = Object.assign({}, DEFAULT_OPTIONS, inOptions)

  if (!validateOptions(options)) {
    return Promise.reject(new Error('Input options are invalid or missing.'))
  }

  const self = {
    shutdown: () => options.ws.terminate(),
  }

  const callback = inCallback.bind(self)

  const executeTheCallback = type => result => {
    return Promise.resolve(callback(type, result))
  }

  return apiLogin(options)
    .then(executeTheCallback('login'))
    .then(() => apiBootstrap(options))
    .then(executeTheCallback('bootstrap'))
    .then(() => apiWebSocket(options, callback))
}
