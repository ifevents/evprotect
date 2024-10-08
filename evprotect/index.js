import { context, AbortController, ALPNProtocol } from '@adobe/fetch'
import { WebSocket } from 'ws'
import createDebugger from 'debug'

const debug = createDebugger('ifevents/evprotect')

const { fetch } = context({
  alpnProtocols: [ALPNProtocol.ALPN_HTTP2],
  rejectUnauthorized: false,
  userAgent: 'ifevents/evprotect',
})

const DEFAULT_OPTIONS = {
  timeout: 5000,
}

const evprotect = inOptions => {
  const options = Object.assign({}, DEFAULT_OPTIONS, inOptions)
  const bootstrap = { login: {} }

  const apiRequest = (path, inParams = {}) => {
    let abort = null
    let timeout = null

    const params = Object.assign({}, inParams)
    const uri = `https://${options.domain}${path}`

    if (!params.signal) {
      abort = new AbortController()
      params.signal = abort.signal
      timeout = setTimeout(() => abort.abort(), options.timeout)
    }

    const clearAbortTimer = result => {
      if (timeout) clearTimeout(timeout)
      return result
    }

    // we are rejecting with the request object so calling functions can
    // inspect it and throw an Error object that makes sense in context
    const rejectIfNotOk = request => {
      return request.ok ? request : Promise.reject(request)
    }

    return fetch(uri, params)
      .then(clearAbortTimer)
      .then(rejectIfNotOk)
  }

  const apiLogin = () => {
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
        options.csrf = csrf
      }

      return request
    }

    return apiRequest('/api/auth/login', params)
      .then(captureToken)
      .then(captureCSRFToken)
      .then(result => result.json())
  }

  const apiBootstrap = () => {
    const params = {
      headers: { cookie: `TOKEN=${options.token}` },
      method: 'GET',
    }

    if (options.csrf) {
      params.headers['x-csrf-token'] = options.csrf
    }

    const captureUpdateId = result => {
      options.lastUpdateId = result.lastUpdateId
      return result
    }

    return apiRequest('/proxy/protect/api/bootstrap', params)
      .then(result => result.json())
      .then(captureUpdateId)
  }

  const generateWebSocketUri = (domain, lastUpdateId) => (
    `https://${domain}/proxy/protect/ws/updates?lastUpdateId=${lastUpdateId}`
  )

  const apiWebSocket = callback => {
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

      if (header.action === 'update' && header.modelKey !== 'event') {
        if (header.modelKey === 'nvr') {
          Object.assign(bootstrap, data)
        }
        else {
          const subArray = bootstrap[`${header.modelKey}s`]
          if (!subArray) return payload

          const subObject = subArray.find(e => e.id === header.id)
          if (!subObject) return payload

          Object.assign(subObject, data)
        }
      }

      return callback(`/protect/${header.modelKey}/${header.id}/${header.action}`, bootstrap, { header, data })
    })

    options.ws.on('error', err => console.log(err))
  }

  const self = {
    shutdown: () => options.ws.terminate(),
  }

  return inCallback => {
    const callback = inCallback.bind(self)
    return apiLogin(options)
      .then(result => Object.assign(bootstrap.login, result))
      .then(() => apiBootstrap())
      .then(result => Object.assign(bootstrap, result))
      .then(() => apiWebSocket(callback))
  }
}

export default evprotect
