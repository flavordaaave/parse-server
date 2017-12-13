import Parse from 'parse/node'
import LRU from 'lru-cache'
import jwt from 'jsonwebtoken'
import logger from '../logger'

const formatKey = key => {
  const beginKey = '-----BEGIN PUBLIC KEY-----'
  const endKey = '-----END PUBLIC KEY-----'

  const sanatizedKey = key
    .replace(beginKey, '')
    .replace(endKey, '')
    .replace('\n', '')

  const keyArray = sanatizedKey.split('').map((l, i) => {
    const position = i + 1
    const isLastCharacter = sanatizedKey.length === position
    if (position % 64 === 0 || isLastCharacter) {
      return l + '\n'
    }
    return l
  })

  return `${beginKey}\n${keyArray.join('')}${endKey}\n`
}

function userForSessionToken(sessionToken) {
  return new Promise((resolve, reject) => {
    if (!sessionToken) return reject(new Error('sessionToken is missing.'))
    jwt.verify(
      sessionToken,
      formatKey(process.env.JWT_PUB_KEY),
      { algorithms: ['ES512'] },
      function(err, decoded) {
        if (err) return reject(err)
        const id = decoded.sub
        return resolve({
          id,
          sessionToken,
        })
      }
    )
  })

  var q = new Parse.Query('_Session')
  q.equalTo('sessionToken', sessionToken)
  return q.first({ useMasterKey: true }).then(function(session) {
    if (!session) {
      return Parse.Promise.error('No session found for session token')
    }
    return session.get('user')
  })
}

class SessionTokenCache {
  cache: Object

  constructor(
    timeout: number = 30 * 24 * 60 * 60 * 1000,
    maxSize: number = 10000
  ) {
    this.cache = new LRU({
      max: maxSize,
      maxAge: timeout,
    })
  }

  getUserId(sessionToken: string): any {
    if (!sessionToken) {
      return Parse.Promise.error('Empty sessionToken')
    }
    const userId = this.cache.get(sessionToken)
    if (userId) {
      logger.verbose(
        'Fetch userId %s of sessionToken %s from Cache',
        userId,
        sessionToken
      )
      return Parse.Promise.as(userId)
    }
    return userForSessionToken(sessionToken).then(
      user => {
        logger.verbose(
          'Fetch userId %s of sessionToken %s from Parse',
          user.id,
          sessionToken
        )
        const userId = user.id
        this.cache.set(sessionToken, userId)
        return Parse.Promise.as(userId)
      },
      error => {
        logger.error(
          'Can not fetch userId for sessionToken %j, error %j',
          sessionToken,
          error
        )
        return Parse.Promise.error(error)
      }
    )
  }
}

export { SessionTokenCache }
