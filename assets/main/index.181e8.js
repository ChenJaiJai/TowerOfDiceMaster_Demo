System.register("chunks:///_virtual/aes.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, BlockCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BlockCipher = module.BlockCipher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "d2c4cBkR9VLsqnrpKoZ2z5c", "aes", undefined);

      // Lookup tables
      var _SBOX = [];
      var INV_SBOX = [];
      var _SUB_MIX_0 = [];
      var _SUB_MIX_1 = [];
      var _SUB_MIX_2 = [];
      var _SUB_MIX_3 = [];
      var INV_SUB_MIX_0 = [];
      var INV_SUB_MIX_1 = [];
      var INV_SUB_MIX_2 = [];
      var INV_SUB_MIX_3 = [];

      // Compute lookup tables

      // Compute double table
      var d = [];
      for (var i = 0; i < 256; i += 1) {
        if (i < 128) {
          d[i] = i << 1;
        } else {
          d[i] = i << 1 ^ 0x11b;
        }
      }

      // Walk GF(2^8)
      var x = 0;
      var xi = 0;
      for (var _i = 0; _i < 256; _i += 1) {
        // Compute sbox
        var sx = xi ^ xi << 1 ^ xi << 2 ^ xi << 3 ^ xi << 4;
        sx = sx >>> 8 ^ sx & 0xff ^ 0x63;
        _SBOX[x] = sx;
        INV_SBOX[sx] = x;

        // Compute multiplication
        var x2 = d[x];
        var x4 = d[x2];
        var x8 = d[x4];

        // Compute sub bytes, mix columns tables
        var t = d[sx] * 0x101 ^ sx * 0x1010100;
        _SUB_MIX_0[x] = t << 24 | t >>> 8;
        _SUB_MIX_1[x] = t << 16 | t >>> 16;
        _SUB_MIX_2[x] = t << 8 | t >>> 24;
        _SUB_MIX_3[x] = t;

        // Compute inv sub bytes, inv mix columns tables
        t = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
        INV_SUB_MIX_0[sx] = t << 24 | t >>> 8;
        INV_SUB_MIX_1[sx] = t << 16 | t >>> 16;
        INV_SUB_MIX_2[sx] = t << 8 | t >>> 24;
        INV_SUB_MIX_3[sx] = t;

        // Compute next counter
        if (!x) {
          xi = 1;
          x = xi;
        } else {
          x = x2 ^ d[d[d[x8 ^ x2]]];
          xi ^= d[d[xi]];
        }
      }

      // Precomputed Rcon lookup
      var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

      /**
       * AES block cipher algorithm.
       */
      var AESAlgo = exports('AESAlgo', /*#__PURE__*/function (_BlockCipher) {
        _inheritsLoose(AESAlgo, _BlockCipher);
        function AESAlgo() {
          return _BlockCipher.apply(this, arguments) || this;
        }
        var _proto = AESAlgo.prototype;
        _proto._doReset = function _doReset() {
          var t;

          // Skip reset of nRounds has been set before and key did not change
          if (this._nRounds && this._keyPriorReset === this._key) {
            return;
          }

          // Shortcuts
          this._keyPriorReset = this._key;
          var key = this._keyPriorReset;
          var keyWords = key.words;
          var keySize = key.sigBytes / 4;

          // Compute number of rounds
          this._nRounds = keySize + 6;
          var nRounds = this._nRounds;

          // Compute number of key schedule rows
          var ksRows = (nRounds + 1) * 4;

          // Compute key schedule
          this._keySchedule = [];
          var keySchedule = this._keySchedule;
          for (var ksRow = 0; ksRow < ksRows; ksRow += 1) {
            if (ksRow < keySize) {
              keySchedule[ksRow] = keyWords[ksRow];
            } else {
              t = keySchedule[ksRow - 1];
              if (!(ksRow % keySize)) {
                // Rot word
                t = t << 8 | t >>> 24;

                // Sub word
                t = _SBOX[t >>> 24] << 24 | _SBOX[t >>> 16 & 0xff] << 16 | _SBOX[t >>> 8 & 0xff] << 8 | _SBOX[t & 0xff];

                // Mix Rcon
                t ^= RCON[ksRow / keySize | 0] << 24;
              } else if (keySize > 6 && ksRow % keySize === 4) {
                // Sub word
                t = _SBOX[t >>> 24] << 24 | _SBOX[t >>> 16 & 0xff] << 16 | _SBOX[t >>> 8 & 0xff] << 8 | _SBOX[t & 0xff];
              }
              keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
            }
          }

          // Compute inv key schedule
          this._invKeySchedule = [];
          var invKeySchedule = this._invKeySchedule;
          for (var invKsRow = 0; invKsRow < ksRows; invKsRow += 1) {
            var _ksRow = ksRows - invKsRow;
            if (invKsRow % 4) {
              t = keySchedule[_ksRow];
            } else {
              t = keySchedule[_ksRow - 4];
            }
            if (invKsRow < 4 || _ksRow <= 4) {
              invKeySchedule[invKsRow] = t;
            } else {
              invKeySchedule[invKsRow] = INV_SUB_MIX_0[_SBOX[t >>> 24]] ^ INV_SUB_MIX_1[_SBOX[t >>> 16 & 0xff]] ^ INV_SUB_MIX_2[_SBOX[t >>> 8 & 0xff]] ^ INV_SUB_MIX_3[_SBOX[t & 0xff]];
            }
          }
        };
        _proto.encryptBlock = function encryptBlock(M, offset) {
          this._doCryptBlock(M, offset, this._keySchedule, _SUB_MIX_0, _SUB_MIX_1, _SUB_MIX_2, _SUB_MIX_3, _SBOX);
        };
        _proto.decryptBlock = function decryptBlock(M, offset) {
          var _M = M;

          // Swap 2nd and 4th rows
          var t = _M[offset + 1];
          _M[offset + 1] = _M[offset + 3];
          _M[offset + 3] = t;
          this._doCryptBlock(_M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

          // Inv swap 2nd and 4th rows
          t = _M[offset + 1];
          _M[offset + 1] = _M[offset + 3];
          _M[offset + 3] = t;
        };
        _proto._doCryptBlock = function _doCryptBlock(M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
          var _M = M;

          // Shortcut
          var nRounds = this._nRounds;

          // Get input, add round key
          var s0 = _M[offset] ^ keySchedule[0];
          var s1 = _M[offset + 1] ^ keySchedule[1];
          var s2 = _M[offset + 2] ^ keySchedule[2];
          var s3 = _M[offset + 3] ^ keySchedule[3];

          // Key schedule row counter
          var ksRow = 4;

          // Rounds
          for (var round = 1; round < nRounds; round += 1) {
            // Shift rows, sub bytes, mix columns, add round key
            var _t = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[s1 >>> 16 & 0xff] ^ SUB_MIX_2[s2 >>> 8 & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t2 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[s2 >>> 16 & 0xff] ^ SUB_MIX_2[s3 >>> 8 & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t3 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[s3 >>> 16 & 0xff] ^ SUB_MIX_2[s0 >>> 8 & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;
            var _t4 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[s0 >>> 16 & 0xff] ^ SUB_MIX_2[s1 >>> 8 & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow];
            ksRow += 1;

            // Update state
            s0 = _t;
            s1 = _t2;
            s2 = _t3;
            s3 = _t4;
          }

          // Shift rows, sub bytes, add round key
          var t0 = (SBOX[s0 >>> 24] << 24 | SBOX[s1 >>> 16 & 0xff] << 16 | SBOX[s2 >>> 8 & 0xff] << 8 | SBOX[s3 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t1 = (SBOX[s1 >>> 24] << 24 | SBOX[s2 >>> 16 & 0xff] << 16 | SBOX[s3 >>> 8 & 0xff] << 8 | SBOX[s0 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t2 = (SBOX[s2 >>> 24] << 24 | SBOX[s3 >>> 16 & 0xff] << 16 | SBOX[s0 >>> 8 & 0xff] << 8 | SBOX[s1 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;
          var t3 = (SBOX[s3 >>> 24] << 24 | SBOX[s0 >>> 16 & 0xff] << 16 | SBOX[s1 >>> 8 & 0xff] << 8 | SBOX[s2 & 0xff]) ^ keySchedule[ksRow];
          ksRow += 1;

          // Set output
          _M[offset] = t0;
          _M[offset + 1] = t1;
          _M[offset + 2] = t2;
          _M[offset + 3] = t3;
        };
        return AESAlgo;
      }(BlockCipher));
      AESAlgo.keySize = 256 / 32;

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
       */
      var AES = exports('AES', BlockCipher._createHelper(AESAlgo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/asn1.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './errors.ts'], function (exports) {
  var _asyncToGenerator, _regeneratorRuntime, cclegacy, JOSENotSupported;
  return {
    setters: [function (module) {
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      JOSENotSupported = module.JOSENotSupported;
    }],
    execute: function () {
      cclegacy._RF.push({}, "8b467c+dupBF4avXB5b8CaM", "asn1", undefined); // import crypto, { isCryptoKey } from './webcrypto'
      // import { types } from './is_key_like'

      // const genericExport = async (
      //   keyType: 'private' | 'public',
      //   keyFormat: 'spki' | 'pkcs8',
      //   key: unknown,
      // ) => {
      //   if (!isCryptoKey(key)) {
      //     throw new TypeError(invalidKeyInput(key, ...types))
      //   }

      //   if (!key.extractable) {
      //     throw new TypeError('CryptoKey is not extractable')
      //   }

      //   if (key.type !== keyType) {
      //     throw new TypeError(`key is not a ${keyType} key`)
      //   }

      //   return formatPEM(
      //     encodeBase64(new Uint8Array(await crypto.subtle.exportKey(keyFormat, key))),
      //     `${keyType.toUpperCase()} KEY`,
      //   )
      // }

      // export const toSPKI: PEMExportFunction = (key) => {
      //   return genericExport('public', 'spki', key)
      // }

      // export const toPKCS8: PEMExportFunction = (key) => {
      //   return genericExport('private', 'pkcs8', key)
      // }
      var findOid = function findOid(keyData, oid, from) {
        if (from === void 0) {
          from = 0;
        }
        if (from === 0) {
          oid.unshift(oid.length);
          oid.unshift(0x06);
        }
        var i = keyData.indexOf(oid[0], from);
        if (i === -1) return false;
        var sub = keyData.subarray(i, i + oid.length);
        if (sub.length !== oid.length) return false;
        return sub.every(function (value, index) {
          return value === oid[index];
        }) || findOid(keyData, oid, i + 1);
      };
      var getNamedCurve = function getNamedCurve(keyData) {
        switch (true) {
          case findOid(keyData, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]):
            return 'P-256';
          case findOid(keyData, [0x2b, 0x81, 0x04, 0x00, 0x22]):
            return 'P-384';
          case findOid(keyData, [0x2b, 0x81, 0x04, 0x00, 0x23]):
            return 'P-521';
          case findOid(keyData, [0x2b, 0x65, 0x6e]):
            return 'X25519';
          case findOid(keyData, [0x2b, 0x65, 0x6f]):
            return 'X448';
          case findOid(keyData, [0x2b, 0x65, 0x70]):
            return 'Ed25519';
          case findOid(keyData, [0x2b, 0x65, 0x71]):
            return 'Ed448';
          default:
            throw new JOSENotSupported('Invalid or unsupported EC Key Curve or OKP Key Sub Type');
        }
      };
      var genericImport = /*#__PURE__*/function () {
        var _ref = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(replace, keyFormat, pem, alg, options) {
          var _options$extractable;
          var algorithm, keyUsages, keyData, isPublic, namedCurve;
          return _regeneratorRuntime().wrap(function _callee$(_context) {
            while (1) switch (_context.prev = _context.next) {
              case 0:
                keyData = new Uint8Array(atob(pem.replace(replace, '')).split('').map(function (c) {
                  return c.charCodeAt(0);
                }));
                isPublic = keyFormat === 'spki';
                _context.t0 = alg;
                _context.next = _context.t0 === 'PS256' ? 5 : _context.t0 === 'PS384' ? 5 : _context.t0 === 'PS512' ? 5 : _context.t0 === 'RS256' ? 8 : _context.t0 === 'RS384' ? 8 : _context.t0 === 'RS512' ? 8 : _context.t0 === 'RSA-OAEP' ? 11 : _context.t0 === 'RSA-OAEP-256' ? 11 : _context.t0 === 'RSA-OAEP-384' ? 11 : _context.t0 === 'RSA-OAEP-512' ? 11 : _context.t0 === 'ES256' ? 14 : _context.t0 === 'ES384' ? 17 : _context.t0 === 'ES512' ? 20 : _context.t0 === 'ECDH-ES' ? 23 : _context.t0 === 'ECDH-ES+A128KW' ? 23 : _context.t0 === 'ECDH-ES+A192KW' ? 23 : _context.t0 === 'ECDH-ES+A256KW' ? 23 : _context.t0 === 'EdDSA' ? 27 : 30;
                break;
              case 5:
                algorithm = {
                  name: 'RSA-PSS',
                  hash: "SHA-" + alg.slice(-3)
                };
                keyUsages = isPublic ? ['verify'] : ['sign'];
                return _context.abrupt("break", 31);
              case 8:
                algorithm = {
                  name: 'RSASSA-PKCS1-v1_5',
                  hash: "SHA-" + alg.slice(-3)
                };
                keyUsages = isPublic ? ['verify'] : ['sign'];
                return _context.abrupt("break", 31);
              case 11:
                algorithm = {
                  name: 'RSA-OAEP',
                  hash: "SHA-" + (parseInt(alg.slice(-3), 10) || 1)
                };
                keyUsages = isPublic ? ['encrypt', 'wrapKey'] : ['decrypt', 'unwrapKey'];
                return _context.abrupt("break", 31);
              case 14:
                algorithm = {
                  name: 'ECDSA',
                  namedCurve: 'P-256'
                };
                keyUsages = isPublic ? ['verify'] : ['sign'];
                return _context.abrupt("break", 31);
              case 17:
                algorithm = {
                  name: 'ECDSA',
                  namedCurve: 'P-384'
                };
                keyUsages = isPublic ? ['verify'] : ['sign'];
                return _context.abrupt("break", 31);
              case 20:
                algorithm = {
                  name: 'ECDSA',
                  namedCurve: 'P-521'
                };
                keyUsages = isPublic ? ['verify'] : ['sign'];
                return _context.abrupt("break", 31);
              case 23:
                namedCurve = getNamedCurve(keyData);
                algorithm = namedCurve.startsWith('P-') ? {
                  name: 'ECDH',
                  namedCurve: namedCurve
                } : {
                  name: namedCurve
                };
                keyUsages = isPublic ? [] : ['deriveBits'];
                return _context.abrupt("break", 31);
              case 27:
                algorithm = {
                  name: getNamedCurve(keyData)
                };
                keyUsages = isPublic ? ['verify'] : ['sign'];
                return _context.abrupt("break", 31);
              case 30:
                throw new JOSENotSupported('Invalid or unsupported "alg" (Algorithm) value');
              case 31:
                return _context.abrupt("return", crypto.subtle.importKey(keyFormat, keyData, algorithm, (_options$extractable = options == null ? void 0 : options.extractable) != null ? _options$extractable : false, keyUsages));
              case 32:
              case "end":
                return _context.stop();
            }
          }, _callee);
        }));
        return function genericImport(_x, _x2, _x3, _x4, _x5) {
          return _ref.apply(this, arguments);
        };
      }();
      var fromPKCS8 = exports('fromPKCS8', function fromPKCS8(pem, alg, options) {
        return genericImport(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, 'pkcs8', pem, alg, options);
      });

      // export const fromSPKI: PEMImportFunction = (pem, alg, options?) => {
      //   return genericImport(/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g, 'spki', pem, alg, options)
      // }

      // function getElement(seq: Uint8Array) {
      //   const result = []
      //   let next = 0

      //   while (next < seq.length) {
      //     const nextPart = parseElement(seq.subarray(next))
      //     result.push(nextPart)
      //     next += nextPart.byteLength
      //   }
      //   return result
      // }

      // function parseElement(bytes: Uint8Array) {
      //   let position = 0

      //   // tag
      //   let tag = bytes[0] & 0x1f
      //   position++
      //   if (tag === 0x1f) {
      //     tag = 0
      //     while (bytes[position] >= 0x80) {
      //       tag = tag * 128 + bytes[position] - 0x80
      //       position++
      //     }
      //     tag = tag * 128 + bytes[position] - 0x80
      //     position++
      //   }

      //   // length
      //   let length = 0
      //   if (bytes[position] < 0x80) {
      //     length = bytes[position]
      //     position++
      //   } else if (length === 0x80) {
      //     length = 0

      //     while (bytes[position + length] !== 0 || bytes[position + length + 1] !== 0) {
      //       if (length > bytes.byteLength) {
      //         throw new TypeError('invalid indefinite form length')
      //       }
      //       length++
      //     }

      //     const byteLength = position + length + 2
      //     return {
      //       byteLength,
      //       contents: bytes.subarray(position, position + length),
      //       raw: bytes.subarray(0, byteLength),
      //     }
      //   } else {
      //     const numberOfDigits = bytes[position] & 0x7f
      //     position++
      //     length = 0
      //     for (let i = 0; i < numberOfDigits; i++) {
      //       length = length * 256 + bytes[position]
      //       position++
      //     }
      //   }

      //   const byteLength = position + length
      //   return {
      //     byteLength,
      //     contents: bytes.subarray(position, byteLength),
      //     raw: bytes.subarray(0, byteLength),
      //   }
      // }

      // function spkiFromX509(buf: Uint8Array) {
      //   const tbsCertificate = getElement(getElement(parseElement(buf).contents)[0].contents)
      //   return encodeBase64(tbsCertificate[tbsCertificate[0].raw[0] === 0xa0 ? 6 : 5].raw)
      // }

      // function getSPKI(x509: string): string {
      //   const pem = x509.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, '')
      //   const raw = decodeBase64(pem)
      //   return formatPEM(spkiFromX509(raw), 'PUBLIC KEY')
      // }

      // export const fromX509: PEMImportFunction = (pem, alg, options?) => {
      //   let spki: string
      //   try {
      //     spki = getSPKI(pem)
      //   } catch (cause) {
      //     // @ts-ignore
      //     throw new TypeError('Failed to parse the X.509 certificate', { cause })
      //   }
      //   return fromSPKI(spki, alg, options)
      // }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/AutoFollow.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, Node, v3, UITransform, Label, Sprite, Component;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Node = module.Node;
      v3 = module.v3;
      UITransform = module.UITransform;
      Label = module.Label;
      Sprite = module.Sprite;
      Component = module.Component;
    }],
    execute: function () {
      var _dec, _class2;
      cclegacy._RF.push({}, "5c77awMzlhAVY94V85jbqoV", "AutoFollow", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var AutoFollow = exports('default', (_dec = ccclass('AF'), _dec(_class2 = /*#__PURE__*/function (_Component2) {
        _inheritsLoose(AutoFollow, _Component2);
        function AutoFollow() {
          var _this2;
          for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
            args[_key2] = arguments[_key2];
          }
          _this2 = _Component2.call.apply(_Component2, [this].concat(args)) || this;
          _this2.target = void 0;
          _this2.isAutoScale = true;
          _this2.isAutoRotation = true;
          _this2.isAutoContentSize = false;
          // opacityValue: number
          // opacity: UIOpacity
          _this2.label = void 0;
          _this2.sprite = void 0;
          _this2.cLabel = void 0;
          _this2.cSprite = void 0;
          _this2.uiTran = void 0;
          _this2.targetTran = void 0;
          _this2.targetClass = void 0;
          return _this2;
        }
        var _proto = AutoFollow.prototype;
        _proto.setTarget = function setTarget(_node) {
          this.target = _node;
          return this;
        };
        _proto.createNewTarget = function createNewTarget() {
          this.target = new Node();
          this.setAndGetComponent();
          this.targetTran.setContentSize(this.uiTran.contentSize);
          this.targetClass.originNode = this.node;
          this.target.name = this.name;
          this.node.parent.addChild(this.target);
          this.target.setPosition(this.node.position);
          this.target.setScale(this.node.scale);
          return this;
        };
        _proto.setAutoScale = function setAutoScale(isbool) {
          this.isAutoScale = isbool;
          return this;
        };
        _proto.setAutoRotation = function setAutoRotation(isbool) {
          this.isAutoRotation = isbool;
          return this;
        };
        _proto.setAutoContentSize = function setAutoContentSize(isbool) {
          this.isAutoContentSize = isbool;
          return this;
        };
        _proto.lateUpdate = function lateUpdate() {
          this.refreshNodeState();
        };
        _proto.checkParentActive = function checkParentActive(node) {
          if (node.parent) {
            if (this.checkParentActive(node.parent)) return node.active;else return false;
          } else return node.active;
        };
        _proto.checkParentScale = function checkParentScale(node) {
          if (node.parent) {
            var parentScale = this.checkParentScale(node.parent);
            if (parentScale == v3(1, 1, 1)) return node.getScale();
            var selfScale = node.getScale();
            return selfScale.multiply(parentScale);
          } else {
            return node.getScale();
          }
        };
        _proto.refreshNodeState = function refreshNodeState() {
          //確認follow對象的active狀態
          var isActive = this.checkParentActive(this.target) && this.targetClass.isCanSee;
          //同步座標
          var pos = this.to2DConvertOtherNodeSpaceAR(this.node, this.target);
          if (this.node.position != pos) this.node.setPosition(pos);
          //如果設定為scale跟隨follow對象，同步對象scale值
          if (this.isAutoScale) {
            var scale = this.checkParentScale(this.target);
            if (scale != this.node.scale) this.node.setScale(scale);
          }
          //如果設定為rotation跟隨follow對象，同步對象rotation值
          if (this.isAutoRotation) {
            if (this.node.worldRotation != this.target.worldRotation) this.node.setWorldRotation(this.target.worldRotation);
          }
          //如果設定為follow對象content跟隨自身，同步對象content值及錨點
          if (this.isAutoContentSize) {
            if (this.targetTran.contentSize != this.uiTran.contentSize) {
              this.targetTran.contentSize = this.uiTran.contentSize;
              this.targetTran.setAnchorPoint(this.uiTran.anchorPoint);
            }
          }
          // if (isActive) this.opacity.opacity = this.opacityValue
          // else this.opacity.opacity = 0

          if (this.label) this.label.enabled = isActive;
          if (this.sprite) {
            this.sprite.enabled = isActive;
          }
          if (this.cLabel) this.cLabel.forEach(function (label) {
            label.enabled = isActive;
          });
          if (this.cSprite) this.cSprite.forEach(function (sprite) {
            sprite.enabled = isActive;
          });
        }
        /**
         * @param targetNode 需要移動的物件
         * @param moveToNode 移動的目的地
         * @returns 
         */;
        _proto.to2DConvertOtherNodeSpaceAR = function to2DConvertOtherNodeSpaceAR(targetNode, moveToNode) {
          //轉成世界座標
          var worldPoint = moveToNode.parent.getComponent(UITransform).convertToWorldSpaceAR(moveToNode.position);
          return targetNode.parent.getComponent(UITransform).convertToNodeSpaceAR(worldPoint);
        };
        _proto.setAndGetComponent = function setAndGetComponent() {
          // if (!this.node.getComponent(UIOpacity)) this.node.addComponent(UIOpacity)
          // this.opacity = this.node.getComponent(UIOpacity)
          // this.opacityValue = this.opacity.opacity
          this.label = this.node.getComponent(Label);
          this.sprite = this.node.getComponent(Sprite);
          this.cLabel = this.node.getComponentsInChildren(Label);
          this.cSprite = this.node.getComponentsInChildren(Sprite);
          this.uiTran = this.node.getComponent(UITransform);
          this.targetTran = this.target.getComponent(UITransform);
          if (!this.targetTran) this.targetTran = this.target.addComponent(UITransform);
          this.targetClass = this.target.getComponent(TheTarget);
          if (!this.targetClass) this.targetClass = this.target.addComponent(TheTarget);
          return this;
        };
        return AutoFollow;
      }(Component)) || _class2));
      var TheTarget = exports('TheTarget', /*#__PURE__*/function (_Component) {
        _inheritsLoose(TheTarget, _Component);
        function TheTarget() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _this.originNode = void 0;
          _this.isCanSee = true;
          return _this;
        }
        return TheTarget;
      }(Component));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/AutoView.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, sys, view, ResolutionPolicy, find, UITransform, Component;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      sys = module.sys;
      view = module.view;
      ResolutionPolicy = module.ResolutionPolicy;
      find = module.find;
      UITransform = module.UITransform;
      Component = module.Component;
    }],
    execute: function () {
      var _dec, _class, _class2, _descriptor, _descriptor2, _descriptor3;
      cclegacy._RF.push({}, "e85a8+VNjFDW6cwoa2Se1YZ", "AutoView", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var AutoView = exports('default', (_dec = ccclass('AutoView'), _dec(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(AutoView, _Component);
        function AutoView() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "BaseViewHeight", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "BaseViewWidth", _descriptor2, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "isAutoView", _descriptor3, _assertThisInitialized(_this));
          _this.curDR = null;
          _this.isCanUpdata = true;
          return _this;
        }
        var _proto = AutoView.prototype;
        _proto.onLoad = function onLoad() {
          //判斷使用者是否有設定，沒有設定就會有基礎的判斷
          this.BaseViewHeight = this.BaseViewHeight == 0 ? 1280 : this.BaseViewHeight;
          this.BaseViewWidth = this.BaseViewWidth == 0 ? 720 : this.BaseViewWidth;
        };
        _proto.start = function start() {
          if (sys.isMobile) view.setResolutionPolicy(ResolutionPolicy.FIXED_WIDTH);else view.setResolutionPolicy(ResolutionPolicy.FIXED_HEIGHT);
          return;
          // view.on('canvas-resize', this.resize, this);
          // director.on(Director.EVENT_AFTER_SCENE_LAUNCH, this.AdjustView, this);
        };

        _proto.AdjustView = function AdjustView() {
          // console.log(view.getDesignResolutionSize().height);
          // console.log(view.getDesignResolutionSize().x);

          var canvasSize = this.getWinSize();
          if (!this.curDR) this.curDR = view.getDesignResolutionSize();
          console.log(canvasSize);
          if (canvasSize.width >= this.BaseViewWidth || canvasSize.height / canvasSize.width <= this.BaseViewHeight / this.BaseViewWidth) {
            var width = canvasSize.width * (this.BaseViewHeight / canvasSize.height);
            view.setDesignResolutionSize(width, this.BaseViewHeight, ResolutionPolicy.FIXED_HEIGHT);
            // console.log(width);

            // cvs.width = width;
            // cvs.height = 1280;
          } else {
            var height = canvasSize.height * (this.BaseViewWidth / canvasSize.width);
            // if (height > this.BaseViewHeight)
            //     height = this.BaseViewHeight

            view.setDesignResolutionSize(this.BaseViewWidth, height, ResolutionPolicy.FIXED_HEIGHT);
          }
          var str = "window\u5BEC:" + canvasSize.width + "\n\rwindow\u9AD8:" + canvasSize.height + "\n\rcocos\u5BEC:" + this.curDR.width + "\n\rcocos\u9AD8:" + this.curDR.height;
          // find("資訊", cvs.node).getComponent(Label).string = str;

          // if (canvasSize.height / canvasSize.width <= 16 / 9) {

          // } else {

          //     // if (canvasSize.height / canvasSize.width > 16 / 9 && canvasSize.height / canvasSize.width <= 19.5 / 9) {

          //     //     view.setDesignResolutionSize(720, 1500, ResolutionPolicy.FIXED_WIDTH)
          //     // } else {

          //     //     view.setDesignResolutionSize(720, 1500, ResolutionPolicy.FIXED_HEIGHT)
          //     // }
          //     cvs.width = 720;
          //     cvs.height = 1500;
          // }

          // console.error("HIHI");
          // if ((screen.windowSize.width) >= (720) || (screen.windowSize.height / screen.windowSize.width) <= (1280 / 720)) {
          //     //宽度超出
          //     var width = screen.windowSize.width * (1280 / screen.windowSize.height);
          //     view.setDesignResolutionSize(width, 1280, ResolutionPolicy.FIXED_HEIGHT);
          // } else {
          //     //高度超出
          //     var height = screen.windowSize.height * (720 / screen.windowSize.width);
          //     view.setDesignResolutionSize(720, height, ResolutionPolicy.FIXED_WIDTH);
          // }
        };

        _proto.AdjustView_Old = function AdjustView_Old() {
          var canvasSize = this.getWinSize();
          if (!this.curDR) this.curDR = view.getDesignResolutionSize();
          // console.log(canvasSize);

          var cvs = find('Canvas').getComponent(UITransform);
          if (canvasSize.width >= 720 || canvasSize.height / canvasSize.width <= 1280 / 720) {
            var width = canvasSize.width * (1280 / canvasSize.height);
            view.setDesignResolutionSize(width, 1280, ResolutionPolicy.FIXED_HEIGHT);
            // console.log(width);

            // cvs.width = width;
            // cvs.height = 1280;
          } else {
            var height = canvasSize.height * (720 / canvasSize.width);
            view.setDesignResolutionSize(720, height, ResolutionPolicy.FIXED_HEIGHT);
            // console.log(height);
            // cvs.width = 720;
            // cvs.height = height;
          }

          var str = "window\u5BEC:" + canvasSize.width + "\n\rwindow\u9AD8:" + canvasSize.height + "\n\rcocos\u5BEC:" + this.curDR.width + "\n\rcocos\u9AD8:" + this.curDR.height;
          // find("資訊", cvs.node).getComponent(Label).string = str;

          // if (canvasSize.height / canvasSize.width <= 16 / 9) {

          // } else {

          //     // if (canvasSize.height / canvasSize.width > 16 / 9 && canvasSize.height / canvasSize.width <= 19.5 / 9) {

          //     //     view.setDesignResolutionSize(720, 1500, ResolutionPolicy.FIXED_WIDTH)
          //     // } else {

          //     //     view.setDesignResolutionSize(720, 1500, ResolutionPolicy.FIXED_HEIGHT)
          //     // }
          //     cvs.width = 720;
          //     cvs.height = 1500;
          // }

          // console.error("HIHI");
          // if ((screen.windowSize.width) >= (720) || (screen.windowSize.height / screen.windowSize.width) <= (1280 / 720)) {
          //     //宽度超出
          //     var width = screen.windowSize.width * (1280 / screen.windowSize.height);
          //     view.setDesignResolutionSize(width, 1280, ResolutionPolicy.FIXED_HEIGHT);
          // } else {
          //     //高度超出
          //     var height = screen.windowSize.height * (720 / screen.windowSize.width);
          //     view.setDesignResolutionSize(720, height, ResolutionPolicy.FIXED_WIDTH);
          // }
        }
        // debounce(func: Function) {
        //     let timer;
        //     return function (event) {
        //         if (timer) clearTimeout(timer);
        //         timer = setTimeout(func, 300, event);
        //     };
        // }
        ;

        _proto.resize = function resize() {
          //根据屏幕大小决定适配策略
          //想明白原理，请阅读本文 https://blog.csdn.net/qq_36720848/article/details/89742451
          var cvs = find('Canvas').getComponent(UITransform);
          if (!this.curDR) this.curDR = view.getDesignResolutionSize();

          // console.log(screen);

          var s = view.getFrameSize();
          // console.log(dr);
          // console.log(s);

          var rw = s.width;
          var rh = s.height;
          var finalW = rw;
          var finalH = rh;
          if (rw / rh > this.curDR.width / this.curDR.height) {
            //!#zh: 是否优先将设计分辨率高度撑满视图高度。 */
            //cvs.fitHeight = true;

            //如果更长，则用定高
            finalH = this.curDR.height;
            finalW = finalH * rw / rh;
          } else {
            /*!#zh: 是否优先将设计分辨率宽度撑满视图宽度。 */
            //cvs.fitWidth = true;
            //如果更短，则用定宽
            finalW = this.curDR.width;
            finalH = rh / rw * finalW;
          }
          view.setDesignResolutionSize(finalW, finalH, ResolutionPolicy.UNKNOWN);
          cvs.width = finalW;
          cvs.height = finalH;
        };
        _proto.getWinSize = function getWinSize() {
          return {
            width: window.innerWidth,
            height: window.innerHeight
          };
        };
        _proto.AdjustView_ = function AdjustView_() {
          var canvasSize = this.getWinSize();
          if (!this.curDR) this.curDR = view.getDesignResolutionSize();
          console.log(canvasSize);
          var cvs = find('Canvas').getComponent(UITransform);
          if (canvasSize.width >= this.BaseViewWidth || canvasSize.height / canvasSize.width <= this.BaseViewHeight / this.BaseViewWidth) {
            var width = canvasSize.width * (this.BaseViewHeight / canvasSize.height);
            view.setDesignResolutionSize(width, this.BaseViewHeight, ResolutionPolicy.FIXED_HEIGHT);
          } else {
            var height = canvasSize.height * (this.BaseViewWidth / canvasSize.width);
            view.setDesignResolutionSize(this.BaseViewWidth, height, ResolutionPolicy.FIXED_HEIGHT);
          }
          var str = "window\u5BEC:" + canvasSize.width + "\n\rwindow\u9AD8:" + canvasSize.height + "\n\rcocos\u5BEC:" + this.curDR.width + "\n\rcocos\u9AD8:" + this.curDR.height;
          console.log(str);
        };
        return AutoView;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "BaseViewHeight", [property], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return 0;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "BaseViewWidth", [property], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return 0;
        }
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "isAutoView", [property], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return true;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/base_client.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './connect.ts', './disconnect.ts', './mod.ts', './pingreq.ts', './puback.ts', './pubcomp.ts', './publish.ts', './pubrec.ts', './pubrel.ts', './subscribe.ts', './unsubscribe.ts'], function (exports) {
  var _inheritsLoose, _wrapAsyncGenerator, _createForOfIteratorHelperLoose, _regeneratorRuntime, _asyncToGenerator, _extends, _asyncIterator, cclegacy, encode$6, encode$5, decode, encode$9, encode$8, encode$1, encode$2, encode$7, encode, encode$3, encode$4;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _wrapAsyncGenerator = module.wrapAsyncGenerator;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
      _regeneratorRuntime = module.regeneratorRuntime;
      _asyncToGenerator = module.asyncToGenerator;
      _extends = module.extends;
      _asyncIterator = module.asyncIterator;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      encode$6 = module.encode;
    }, function (module) {
      encode$5 = module.encode;
    }, function (module) {
      decode = module.decode;
    }, function (module) {
      encode$9 = module.encode;
    }, function (module) {
      encode$8 = module.encode;
    }, function (module) {
      encode$1 = module.encode;
    }, function (module) {
      encode$2 = module.encode;
    }, function (module) {
      encode$7 = module.encode;
    }, function (module) {
      encode = module.encode;
    }, function (module) {
      encode$3 = module.encode;
    }, function (module) {
      encode$4 = module.encode;
    }],
    execute: function () {
      cclegacy._RF.push({}, "9c73b1VKGdAu6IyLUpNna/r", "base_client", undefined);
      var packetIdLimit = Math.pow(2, 16);

      // Only used for incoming QoS 2 messages.
      var IncomingStore = exports('IncomingStore', function IncomingStore() {});
      var IncomingMemoryStore = exports('IncomingMemoryStore', /*#__PURE__*/function (_IncomingStore) {
        _inheritsLoose(IncomingMemoryStore, _IncomingStore);
        function IncomingMemoryStore() {
          var _this2;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this2 = _IncomingStore.call.apply(_IncomingStore, [this].concat(args)) || this;
          _this2.packets = new Set();
          return _this2;
        }
        var _proto = IncomingMemoryStore.prototype;
        _proto.store = function store(packetId) {
          this.packets.add(packetId);
          return Promise.resolve();
        };
        _proto.has = function has(packetId) {
          return Promise.resolve(this.packets.has(packetId));
        };
        _proto.discard = function discard(packetId) {
          this.packets["delete"](packetId);
          return Promise.resolve();
        };
        return IncomingMemoryStore;
      }(IncomingStore));

      // Used for outgoing QoS 1 and 2 messages.
      var OutgoingStore = exports('OutgoingStore', function OutgoingStore() {});
      var OutgoingMemoryStore = exports('OutgoingMemoryStore', /*#__PURE__*/function (_OutgoingStore) {
        _inheritsLoose(OutgoingMemoryStore, _OutgoingStore);
        function OutgoingMemoryStore() {
          var _this3;
          for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
            args[_key2] = arguments[_key2];
          }
          _this3 = _OutgoingStore.call.apply(_OutgoingStore, [this].concat(args)) || this;
          _this3.packets = new Map();
          return _this3;
        }
        var _proto2 = OutgoingMemoryStore.prototype;
        _proto2.store = function store(packet) {
          if (!packet.id) {
            return Promise.reject(new Error("missing packet.id"));
          }
          this.packets.set(packet.id, packet);
          return Promise.resolve();
        };
        _proto2.discard = function discard(packetId) {
          this.packets["delete"](packetId);
          return Promise.resolve();
        };
        _proto2.iterate = function iterate() {
          var _this = this;
          return _wrapAsyncGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
            var _iterator2, _step2, value;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  _iterator2 = _createForOfIteratorHelperLoose(_this.packets.values());
                case 1:
                  if ((_step2 = _iterator2()).done) {
                    _context.next = 7;
                    break;
                  }
                  value = _step2.value;
                  _context.next = 5;
                  return value;
                case 5:
                  _context.next = 1;
                  break;
                case 7:
                case "end":
                  return _context.stop();
              }
            }, _callee);
          }))();
        };
        return OutgoingMemoryStore;
      }(OutgoingStore));
      var defaultPorts = {
        mqtt: 1883,
        mqtts: 8883,
        ws: 80,
        wss: 443
      };
      var defaultClientIdPrefix = "mqttts";
      var defaultKeepAlive = 60;
      var defaultConnectTimeout = 10 * 1000;
      var defaultConnectOptions = {
        retries: Infinity,
        minDelay: 1000,
        maxDelay: 2000,
        factor: 1.1,
        random: false
      };
      var defaultReconnectOptions = {
        retries: Infinity,
        minDelay: 1000,
        maxDelay: 60000,
        factor: 1.1,
        random: true
      };

      // deno-lint-ignore no-explicit-any

      var Client = exports('Client', /*#__PURE__*/function () {
        function Client(options) {
          this.options = void 0;
          this.url = void 0;
          this.clientId = void 0;
          this.keepAlive = void 0;
          this.connectionState = "offline";
          this.everConnected = false;
          this.disconnectRequested = false;
          this.reconnectAttempt = 0;
          this.subscriptions = [];
          this.lastPacketId = 0;
          this.lastPacketTime = void 0;
          this.buffer = null;
          this.unresolvedConnect = void 0;
          this.queuedPublishes = [];
          this.unresolvedPublishes = new Map();
          this.incomingStore = void 0;
          this.outgoingStore = void 0;
          this.unresolvedSubscribes = new Map();
          this.unresolvedUnsubscribes = new Map();
          this.unacknowledgedSubscribes = new Map();
          this.unacknowledgedUnsubscribes = new Map();
          this.eventListeners = new Map();
          this.timers = {};
          this.log = void 0;
          // These are the cached encoder and decoders.
          this.utf8Encoder = void 0;
          this.utf8Decoder = void 0;
          this.options = options || {};
          this.clientId = this.generateClientId();
          this.keepAlive = typeof this.options.keepAlive === "number" ? this.options.keepAlive : defaultKeepAlive;
          this.incomingStore = this.options.incomingStore || new IncomingMemoryStore();
          this.outgoingStore = this.options.outgoingStore || new OutgoingMemoryStore();
          this.log = this.options.logger || function () {};
          this.utf8Encoder = this.getUTF8Encoder();
          this.utf8Decoder = this.getUTF8Decoder();
        }
        var _proto3 = Client.prototype;
        _proto3.connect = function connect() {
          switch (this.connectionState) {
            case "offline":
            case "disconnected":
              break;
            default:
              return Promise.reject(new Error("should not be connecting in " + this.connectionState + " state"));
          }
          this.disconnectRequested = false;
          var deferred = new Deferred();
          this.unresolvedConnect = deferred;
          this.openConnection();
          return deferred.promise;
        };
        _proto3.publish = function publish(topic, payload, options) {
          var dup = options && options.dup || false;
          var qos = options && options.qos || 0;
          var retain = options && options.retain || false;
          var id = qos > 0 ? this.nextPacketId() : 0;
          var packet = {
            type: "publish",
            topic: topic,
            payload: payload,
            dup: dup,
            retain: retain,
            qos: qos,
            id: id
          };
          var deferred = new Deferred();
          if (this.connectionState === "connected") {
            this.sendPublish(packet, deferred);
          } else {
            this.log("queueing publish");
            this.queuedPublishes.push({
              packet: packet,
              deferred: deferred
            });
          }
          return deferred.promise;
        };
        _proto3.flushQueuedPublishes = /*#__PURE__*/function () {
          var _flushQueuedPublishes = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee2() {
            var queued, _queued, _packet, deferred;
            return _regeneratorRuntime().wrap(function _callee2$(_context2) {
              while (1) switch (_context2.prev = _context2.next) {
                case 0:
                  if (!(queued = this.queuedPublishes.shift())) {
                    _context2.next = 6;
                    break;
                  }
                  _queued = queued, _packet = _queued.packet, deferred = _queued.deferred;
                  _context2.next = 4;
                  return this.sendPublish(_packet, deferred);
                case 4:
                  _context2.next = 0;
                  break;
                case 6:
                case "end":
                  return _context2.stop();
              }
            }, _callee2, this);
          }));
          function flushQueuedPublishes() {
            return _flushQueuedPublishes.apply(this, arguments);
          }
          return flushQueuedPublishes;
        }();
        _proto3.flushUnacknowledgedPublishes = /*#__PURE__*/function () {
          var _flushUnacknowledgedPublishes = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee3() {
            var _iteratorAbruptCompletion, _didIteratorError, _iteratorError, _iterator, _step, _packet2;
            return _regeneratorRuntime().wrap(function _callee3$(_context3) {
              while (1) switch (_context3.prev = _context3.next) {
                case 0:
                  _iteratorAbruptCompletion = false;
                  _didIteratorError = false;
                  _context3.prev = 2;
                  _iterator = _asyncIterator(this.outgoingStore.iterate());
                case 4:
                  _context3.next = 6;
                  return _iterator.next();
                case 6:
                  if (!(_iteratorAbruptCompletion = !(_step = _context3.sent).done)) {
                    _context3.next = 18;
                    break;
                  }
                  _packet2 = _step.value;
                  if (!(_packet2.type === "publish")) {
                    _context3.next = 13;
                    break;
                  }
                  _context3.next = 11;
                  return this.send(_extends({}, _packet2, {
                    dup: true
                  }), encode$2);
                case 11:
                  _context3.next = 15;
                  break;
                case 13:
                  _context3.next = 15;
                  return this.send(_packet2, encode);
                case 15:
                  _iteratorAbruptCompletion = false;
                  _context3.next = 4;
                  break;
                case 18:
                  _context3.next = 24;
                  break;
                case 20:
                  _context3.prev = 20;
                  _context3.t0 = _context3["catch"](2);
                  _didIteratorError = true;
                  _iteratorError = _context3.t0;
                case 24:
                  _context3.prev = 24;
                  _context3.prev = 25;
                  if (!(_iteratorAbruptCompletion && _iterator["return"] != null)) {
                    _context3.next = 29;
                    break;
                  }
                  _context3.next = 29;
                  return _iterator["return"]();
                case 29:
                  _context3.prev = 29;
                  if (!_didIteratorError) {
                    _context3.next = 32;
                    break;
                  }
                  throw _iteratorError;
                case 32:
                  return _context3.finish(29);
                case 33:
                  return _context3.finish(24);
                case 34:
                case "end":
                  return _context3.stop();
              }
            }, _callee3, this, [[2, 20, 24, 34], [25,, 29, 33]]);
          }));
          function flushUnacknowledgedPublishes() {
            return _flushUnacknowledgedPublishes.apply(this, arguments);
          }
          return flushUnacknowledgedPublishes;
        }();
        _proto3.sendPublish = /*#__PURE__*/function () {
          var _sendPublish = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee4(packet, deferred) {
            return _regeneratorRuntime().wrap(function _callee4$(_context4) {
              while (1) switch (_context4.prev = _context4.next) {
                case 0:
                  if (packet.qos && packet.qos > 0) {
                    this.unresolvedPublishes.set(packet.id, deferred);
                    this.outgoingStore.store(packet);
                  }
                  _context4.next = 3;
                  return this.send(packet, encode$2);
                case 3:
                  if (!packet.qos) {
                    deferred.resolve();
                  }
                case 4:
                case "end":
                  return _context4.stop();
              }
            }, _callee4, this);
          }));
          function sendPublish(_x, _x2) {
            return _sendPublish.apply(this, arguments);
          }
          return sendPublish;
        }();
        _proto3.subscribe = /*#__PURE__*/function () {
          var _subscribe = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee5(input, qos) {
            var _this4 = this;
            var arr, subs, promises, _loop, _iterator3, _step3;
            return _regeneratorRuntime().wrap(function _callee5$(_context6) {
              while (1) switch (_context6.prev = _context6.next) {
                case 0:
                  _context6.t0 = this.connectionState;
                  _context6.next = _context6.t0 === "disconnecting" ? 3 : _context6.t0 === "disconnected" ? 3 : 4;
                  break;
                case 3:
                  throw new Error("should not be subscribing in " + this.connectionState + " state");
                case 4:
                  arr = Array.isArray(input) ? input : [input];
                  subs = arr.map(function (sub) {
                    return typeof sub === "object" ? {
                      topicFilter: sub.topicFilter,
                      qos: sub.qos || qos || 0,
                      state: "pending"
                    } : {
                      topicFilter: sub,
                      qos: qos || 0,
                      state: "pending"
                    };
                  });
                  promises = [];
                  _loop = /*#__PURE__*/_regeneratorRuntime().mark(function _loop() {
                    var sub, deferred;
                    return _regeneratorRuntime().wrap(function _loop$(_context5) {
                      while (1) switch (_context5.prev = _context5.next) {
                        case 0:
                          sub = _step3.value;
                          // Replace any matching subscription so we don't resubscribe to it
                          // multiple times on reconnect. This matches what the broker is supposed
                          // to do when it receives a subscribe packet containing a topic filter
                          // matching an existing subscription.
                          _this4.subscriptions = _this4.subscriptions.filter(function (old) {
                            return old.topicFilter !== sub.topicFilter;
                          });
                          _this4.subscriptions.push(sub);
                          deferred = new Deferred();
                          _this4.unresolvedSubscribes.set(sub.topicFilter, deferred);
                          promises.push(deferred.promise.then(function () {
                            return sub;
                          }));
                        case 6:
                        case "end":
                          return _context5.stop();
                      }
                    }, _loop);
                  });
                  _iterator3 = _createForOfIteratorHelperLoose(subs);
                case 9:
                  if ((_step3 = _iterator3()).done) {
                    _context6.next = 13;
                    break;
                  }
                  return _context6.delegateYield(_loop(), "t1", 11);
                case 11:
                  _context6.next = 9;
                  break;
                case 13:
                  _context6.next = 15;
                  return this.flushSubscriptions();
                case 15:
                  return _context6.abrupt("return", Promise.all(promises));
                case 16:
                case "end":
                  return _context6.stop();
              }
            }, _callee5, this);
          }));
          function subscribe(_x3, _x4) {
            return _subscribe.apply(this, arguments);
          }
          return subscribe;
        }();
        _proto3.flushSubscriptions = /*#__PURE__*/function () {
          var _flushSubscriptions = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee6() {
            var subs;
            return _regeneratorRuntime().wrap(function _callee6$(_context7) {
              while (1) switch (_context7.prev = _context7.next) {
                case 0:
                  subs = this.subscriptions.filter(function (sub) {
                    return sub.state === "pending";
                  });
                  if (!(subs.length > 0 && this.connectionState === "connected")) {
                    _context7.next = 4;
                    break;
                  }
                  _context7.next = 4;
                  return this.sendSubscribe(subs);
                case 4:
                case "end":
                  return _context7.stop();
              }
            }, _callee6, this);
          }));
          function flushSubscriptions() {
            return _flushSubscriptions.apply(this, arguments);
          }
          return flushSubscriptions;
        }();
        _proto3.sendSubscribe = /*#__PURE__*/function () {
          var _sendSubscribe = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee7(subscriptions) {
            var subscribePacket, _iterator4, _step4, sub;
            return _regeneratorRuntime().wrap(function _callee7$(_context8) {
              while (1) switch (_context8.prev = _context8.next) {
                case 0:
                  subscribePacket = {
                    type: "subscribe",
                    id: this.nextPacketId(),
                    subscriptions: subscriptions.map(function (sub) {
                      return {
                        topicFilter: sub.topicFilter,
                        qos: sub.qos
                      };
                    })
                  };
                  this.unacknowledgedSubscribes.set(subscribePacket.id, {
                    subscriptions: subscriptions
                  });
                  _context8.next = 4;
                  return this.send(subscribePacket, encode$3);
                case 4:
                  for (_iterator4 = _createForOfIteratorHelperLoose(subscriptions); !(_step4 = _iterator4()).done;) {
                    sub = _step4.value;
                    sub.state = "unacknowledged";
                  }
                case 5:
                case "end":
                  return _context8.stop();
              }
            }, _callee7, this);
          }));
          function sendSubscribe(_x5) {
            return _sendSubscribe.apply(this, arguments);
          }
          return sendSubscribe;
        }();
        _proto3.unsubscribe = /*#__PURE__*/function () {
          var _unsubscribe = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee8(input) {
            var _this5 = this;
            var arr, promises, _loop2, _iterator5, _step5;
            return _regeneratorRuntime().wrap(function _callee8$(_context10) {
              while (1) switch (_context10.prev = _context10.next) {
                case 0:
                  _context10.t0 = this.connectionState;
                  _context10.next = _context10.t0 === "disconnecting" ? 3 : _context10.t0 === "disconnected" ? 3 : 4;
                  break;
                case 3:
                  throw new Error("should not be unsubscribing in " + this.connectionState + " state");
                case 4:
                  arr = Array.isArray(input) ? input : [input];
                  promises = [];
                  _loop2 = /*#__PURE__*/_regeneratorRuntime().mark(function _loop2() {
                    var topicFilter, sub, deferred, promise;
                    return _regeneratorRuntime().wrap(function _loop2$(_context9) {
                      while (1) switch (_context9.prev = _context9.next) {
                        case 0:
                          topicFilter = _step5.value;
                          sub = _this5.subscriptions.find(function (sub) {
                            return sub.topicFilter === topicFilter;
                          }) || {
                            topicFilter: topicFilter,
                            qos: 0,
                            state: "unknown"
                          };
                          deferred = new Deferred();
                          promise = deferred.promise.then(function () {
                            return sub;
                          });
                          if (!(_this5.connectionState !== "connected" && _this5.options.clean !== false)) {
                            _context9.next = 8;
                            break;
                          }
                          sub.state = "removed";
                          _context9.next = 17;
                          break;
                        case 8:
                          _context9.t0 = sub.state;
                          _context9.next = _context9.t0 === "pending" ? 11 : _context9.t0 === "removed" ? 13 : _context9.t0 === "replaced" ? 13 : _context9.t0 === "unknown" ? 14 : _context9.t0 === "unacknowledged" ? 14 : _context9.t0 === "acknowledged" ? 14 : _context9.t0 === "unsubscribe-pending" ? 16 : _context9.t0 === "unsubscribe-unacknowledged" ? 16 : _context9.t0 === "unsubscribe-acknowledged" ? 16 : 17;
                          break;
                        case 11:
                          sub.state = "removed";
                          return _context9.abrupt("break", 17);
                        case 13:
                          return _context9.abrupt("break", 17);
                        case 14:
                          sub.state = "unsubscribe-pending";
                          return _context9.abrupt("break", 17);
                        case 16:
                          return _context9.abrupt("break", 17);
                        case 17:
                          _this5.unresolvedUnsubscribes.set(topicFilter, deferred);
                          promises.push(promise);
                        case 19:
                        case "end":
                          return _context9.stop();
                      }
                    }, _loop2);
                  });
                  _iterator5 = _createForOfIteratorHelperLoose(arr);
                case 8:
                  if ((_step5 = _iterator5()).done) {
                    _context10.next = 12;
                    break;
                  }
                  return _context10.delegateYield(_loop2(), "t1", 10);
                case 10:
                  _context10.next = 8;
                  break;
                case 12:
                  _context10.next = 14;
                  return this.flushUnsubscriptions();
                case 14:
                  return _context10.abrupt("return", Promise.all(promises));
                case 15:
                case "end":
                  return _context10.stop();
              }
            }, _callee8, this);
          }));
          function unsubscribe(_x6) {
            return _unsubscribe.apply(this, arguments);
          }
          return unsubscribe;
        }();
        _proto3.flushUnsubscriptions = /*#__PURE__*/function () {
          var _flushUnsubscriptions = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee9() {
            var subs, _iterator6, _step6, sub, unresolvedSubscribe, unresolvedUnsubscribe;
            return _regeneratorRuntime().wrap(function _callee9$(_context11) {
              while (1) switch (_context11.prev = _context11.next) {
                case 0:
                  subs = [];
                  for (_iterator6 = _createForOfIteratorHelperLoose(this.subscriptions); !(_step6 = _iterator6()).done;) {
                    sub = _step6.value;
                    if (sub.state === "removed") {
                      unresolvedSubscribe = this.unresolvedSubscribes.get(sub.topicFilter);
                      if (unresolvedSubscribe) {
                        this.unresolvedSubscribes["delete"](sub.topicFilter);
                        unresolvedSubscribe.resolve(null);
                      }
                      unresolvedUnsubscribe = this.unresolvedUnsubscribes.get(sub.topicFilter);
                      if (unresolvedUnsubscribe) {
                        this.unresolvedUnsubscribes["delete"](sub.topicFilter);
                        unresolvedUnsubscribe.resolve(null);
                      }
                    }
                    if (sub.state === "unsubscribe-pending") {
                      subs.push(sub);
                    }
                  }
                  this.subscriptions = this.subscriptions.filter(function (sub) {
                    return sub.state !== "removed";
                  });
                  if (!(subs.length > 0 && this.connectionState === "connected")) {
                    _context11.next = 6;
                    break;
                  }
                  _context11.next = 6;
                  return this.sendUnsubscribe(subs);
                case 6:
                case "end":
                  return _context11.stop();
              }
            }, _callee9, this);
          }));
          function flushUnsubscriptions() {
            return _flushUnsubscriptions.apply(this, arguments);
          }
          return flushUnsubscriptions;
        }();
        _proto3.sendUnsubscribe = /*#__PURE__*/function () {
          var _sendUnsubscribe = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee10(subscriptions) {
            var unsubscribePacket, _iterator7, _step7, sub;
            return _regeneratorRuntime().wrap(function _callee10$(_context12) {
              while (1) switch (_context12.prev = _context12.next) {
                case 0:
                  unsubscribePacket = {
                    type: "unsubscribe",
                    id: this.nextPacketId(),
                    topicFilters: subscriptions.map(function (sub) {
                      return sub.topicFilter;
                    })
                  };
                  this.unacknowledgedUnsubscribes.set(unsubscribePacket.id, {
                    subscriptions: subscriptions
                  });
                  _context12.next = 4;
                  return this.send(unsubscribePacket, encode$4);
                case 4:
                  for (_iterator7 = _createForOfIteratorHelperLoose(subscriptions); !(_step7 = _iterator7()).done;) {
                    sub = _step7.value;
                    sub.state = "unsubscribe-unacknowledged";
                  }
                case 5:
                case "end":
                  return _context12.stop();
              }
            }, _callee10, this);
          }));
          function sendUnsubscribe(_x7) {
            return _sendUnsubscribe.apply(this, arguments);
          }
          return sendUnsubscribe;
        }();
        _proto3.disconnect = /*#__PURE__*/function () {
          var _disconnect = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee11() {
            return _regeneratorRuntime().wrap(function _callee11$(_context13) {
              while (1) switch (_context13.prev = _context13.next) {
                case 0:
                  _context13.t0 = this.connectionState;
                  _context13.next = _context13.t0 === "connected" ? 3 : _context13.t0 === "connecting" ? 6 : _context13.t0 === "offline" ? 8 : 11;
                  break;
                case 3:
                  _context13.next = 5;
                  return this.doDisconnect();
                case 5:
                  return _context13.abrupt("break", 12);
                case 6:
                  this.disconnectRequested = true;
                  return _context13.abrupt("break", 12);
                case 8:
                  this.changeState("disconnected");
                  this.stopTimers();
                  return _context13.abrupt("break", 12);
                case 11:
                  throw new Error("should not be disconnecting in " + this.connectionState + " state");
                case 12:
                case "end":
                  return _context13.stop();
              }
            }, _callee11, this);
          }));
          function disconnect() {
            return _disconnect.apply(this, arguments);
          }
          return disconnect;
        }();
        _proto3.doDisconnect = /*#__PURE__*/function () {
          var _doDisconnect = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee12() {
            return _regeneratorRuntime().wrap(function _callee12$(_context14) {
              while (1) switch (_context14.prev = _context14.next) {
                case 0:
                  this.changeState("disconnecting");
                  this.stopTimers();
                  _context14.next = 4;
                  return this.send({
                    type: "disconnect"
                  }, encode$5);
                case 4:
                  _context14.next = 6;
                  return this.close();
                case 6:
                case "end":
                  return _context14.stop();
              }
            }, _callee12, this);
          }));
          function doDisconnect() {
            return _doDisconnect.apply(this, arguments);
          }
          return doDisconnect;
        }() // Methods implemented by subclasses
        ;

        _proto3.decode = function decode$1(bytes) {
          return decode(bytes, this.utf8Decoder);
        }

        // This gets called from connect and when reconnecting.
        ;

        _proto3.openConnection = /*#__PURE__*/
        function () {
          var _openConnection = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee13() {
            return _regeneratorRuntime().wrap(function _callee13$(_context15) {
              while (1) switch (_context15.prev = _context15.next) {
                case 0:
                  _context15.prev = 0;
                  this.changeState("connecting");
                  this.url = this.getURL();
                  this.log("opening connection to " + this.url);
                  _context15.next = 6;
                  return this.open(this.url);
                case 6:
                  _context15.next = 8;
                  return this.send({
                    type: "connect",
                    clientId: this.clientId,
                    username: this.options.username,
                    password: this.options.password,
                    clean: this.options.clean !== false,
                    keepAlive: this.keepAlive
                  }, encode$6);
                case 8:
                  this.startConnectTimer();
                  _context15.next = 16;
                  break;
                case 11:
                  _context15.prev = 11;
                  _context15.t0 = _context15["catch"](0);
                  this.log("caught error opening connection: " + _context15.t0.message);
                  this.changeState("offline");
                  if (!this.startReconnectTimer()) {
                    this.notifyConnectRejected(new Error("connection failed"));
                  }
                case 16:
                case "end":
                  return _context15.stop();
              }
            }, _callee13, this, [[0, 11]]);
          }));
          function openConnection() {
            return _openConnection.apply(this, arguments);
          }
          return openConnection;
        }() // This gets called when the connection is fully established (after receiving the CONNACK packet).
        ;

        _proto3.connectionEstablished = /*#__PURE__*/
        function () {
          var _connectionEstablished = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee14(connackPacket) {
            var _iterator8, _step8, sub;
            return _regeneratorRuntime().wrap(function _callee14$(_context16) {
              while (1) switch (_context16.prev = _context16.next) {
                case 0:
                  if (this.options.clean !== false || !connackPacket.sessionPresent) {
                    for (_iterator8 = _createForOfIteratorHelperLoose(this.subscriptions); !(_step8 = _iterator8()).done;) {
                      sub = _step8.value;
                      if (sub.state === "unsubscribe-pending") {
                        sub.state = "removed";
                      } else {
                        sub.state = "pending";
                      }
                    }
                  }
                  _context16.next = 3;
                  return this.flushSubscriptions();
                case 3:
                  _context16.next = 5;
                  return this.flushUnsubscriptions();
                case 5:
                  _context16.next = 7;
                  return this.flushUnacknowledgedPublishes();
                case 7:
                  _context16.next = 9;
                  return this.flushQueuedPublishes();
                case 9:
                  if (this.unresolvedConnect) {
                    this.log("resolving initial connect");
                    this.unresolvedConnect.resolve(connackPacket);
                  }
                  if (this.disconnectRequested) {
                    this.doDisconnect();
                  } else {
                    this.startKeepAliveTimer();
                  }
                case 11:
                case "end":
                  return _context16.stop();
              }
            }, _callee14, this);
          }));
          function connectionEstablished(_x8) {
            return _connectionEstablished.apply(this, arguments);
          }
          return connectionEstablished;
        }() // This gets called by subclasses when the connection is unexpectedly closed.
        ;

        _proto3.connectionClosed = function connectionClosed() {
          this.log("connectionClosed");
          switch (this.connectionState) {
            case "disconnecting":
              this.changeState("disconnected");
              break;
            default:
              this.changeState("offline");
              this.reconnectAttempt = 0;
              this.startReconnectTimer();
              break;
          }
          this.stopKeepAliveTimer();
        };
        _proto3.connectionError = function connectionError(error) {
          // TODO: decide what to do with this
          this.log("connectionError", error);
        };
        _proto3.bytesReceived = function bytesReceived(bytes) {
          this.log("bytes received", bytes);
          this.emit("bytesreceived", bytes);
          var buffer = bytes;
          var oldBuffer = this.buffer;
          if (oldBuffer) {
            var newBuffer = new Uint8Array(oldBuffer.length + bytes.length);
            newBuffer.set(oldBuffer);
            newBuffer.set(bytes, oldBuffer.length);
            buffer = newBuffer;
          } else {
            buffer = bytes;
          }
          do {
            var _packet3 = this.decode(buffer);
            if (!_packet3) {
              break;
            }
            this.log("received " + _packet3.type + " packet", _packet3);
            this.packetReceived(_packet3);
            if (_packet3.length < buffer.length) {
              buffer = buffer.slice(_packet3.length);
            } else {
              buffer = null;
            }
          } while (buffer);
          this.buffer = buffer;
        };
        _proto3.packetReceived = function packetReceived(packet) {
          this.emit("packetreceive", packet);
          switch (packet.type) {
            case "connack":
              this.handleConnack(packet);
              break;
            case "publish":
              this.handlePublish(packet);
              break;
            case "puback":
              this.handlePuback(packet);
              break;
            case "pubrec":
              this.handlePubrec(packet);
              break;
            case "pubrel":
              this.handlePubrel(packet);
              break;
            case "pubcomp":
              this.handlePubcomp(packet);
              break;
            case "suback":
              this.handleSuback(packet);
              break;
            case "unsuback":
              this.handleUnsuback(packet);
              break;
          }
        };
        _proto3.protocolViolation = function protocolViolation(msg) {
          this.log("protocolViolation", msg);
        };
        _proto3.handleConnack = function handleConnack(packet) {
          switch (this.connectionState) {
            case "connecting":
              break;
            default:
              throw new Error("should not be receiving connack packets in " + this.connectionState + " state");
          }
          this.changeState("connected");
          this.everConnected = true;
          this.stopConnectTimer();
          this.connectionEstablished(packet);
        };
        _proto3.handlePublish = /*#__PURE__*/function () {
          var _handlePublish = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee15(packet) {
            var emitMessage;
            return _regeneratorRuntime().wrap(function _callee15$(_context17) {
              while (1) switch (_context17.prev = _context17.next) {
                case 0:
                  if (!(packet.qos === 0)) {
                    _context17.next = 4;
                    break;
                  }
                  this.emit("message", packet.topic, packet.payload, packet);
                  _context17.next = 22;
                  break;
                case 4:
                  if (!(packet.qos === 1)) {
                    _context17.next = 11;
                    break;
                  }
                  if (!(typeof packet.id !== "number" || packet.id < 1)) {
                    _context17.next = 7;
                    break;
                  }
                  return _context17.abrupt("return", this.protocolViolation("publish packet with qos 1 is missing id"));
                case 7:
                  this.emit("message", packet.topic, packet.payload, packet);
                  this.send({
                    type: "puback",
                    id: packet.id
                  }, encode$8);
                  _context17.next = 22;
                  break;
                case 11:
                  if (!(packet.qos === 2)) {
                    _context17.next = 22;
                    break;
                  }
                  if (!(typeof packet.id !== "number" || packet.id < 1)) {
                    _context17.next = 14;
                    break;
                  }
                  return _context17.abrupt("return", this.protocolViolation("publish packet with qos 2 is missing id"));
                case 14:
                  _context17.t0 = !packet.dup;
                  if (_context17.t0) {
                    _context17.next = 19;
                    break;
                  }
                  _context17.next = 18;
                  return this.incomingStore.has(packet.id);
                case 18:
                  _context17.t0 = !_context17.sent;
                case 19:
                  emitMessage = _context17.t0;
                  if (emitMessage) {
                    this.incomingStore.store(packet.id);
                    this.emit("message", packet.topic, packet.payload, packet);
                  }
                  this.send({
                    type: "pubrec",
                    id: packet.id
                  }, encode$7);
                case 22:
                case "end":
                  return _context17.stop();
              }
            }, _callee15, this);
          }));
          function handlePublish(_x9) {
            return _handlePublish.apply(this, arguments);
          }
          return handlePublish;
        }();
        _proto3.handlePuback = function handlePuback(packet) {
          this.outgoingStore.discard(packet.id);
          var deferred = this.unresolvedPublishes.get(packet.id);
          if (deferred) {
            this.unresolvedPublishes["delete"](packet.id);
            deferred.resolve();
          } else {
            this.log("received puback packet with unrecognized id " + packet.id);
          }
        };
        _proto3.handlePubrec = function handlePubrec(packet) {
          var pubrel = {
            type: "pubrel",
            id: packet.id
          };
          this.outgoingStore.store(pubrel);
          this.send(pubrel, encode);
        };
        _proto3.handlePubrel = function handlePubrel(packet) {
          this.incomingStore.discard(packet.id);
          this.send({
            type: "pubcomp",
            id: packet.id
          }, encode$1);
        };
        _proto3.handlePubcomp = function handlePubcomp(packet) {
          this.outgoingStore.discard(packet.id);
          var deferred = this.unresolvedPublishes.get(packet.id);
          if (deferred) {
            this.unresolvedPublishes["delete"](packet.id);
            deferred.resolve();
          } else {
            this.log("received pubcomp packet with unrecognized id " + packet.id);
          }
        };
        _proto3.handleSuback = function handleSuback(packet) {
          var unacknowledgedSubscribe = this.unacknowledgedSubscribes.get(packet.id);

          // TODO: verify returnCodes length matches subscriptions.length

          if (unacknowledgedSubscribe) {
            this.unacknowledgedSubscribes["delete"](packet.id);
            var i = 0;
            for (var _iterator9 = _createForOfIteratorHelperLoose(unacknowledgedSubscribe.subscriptions), _step9; !(_step9 = _iterator9()).done;) {
              var sub = _step9.value;
              sub.state = "acknowledged";
              sub.returnCode = packet.returnCodes[i++];
              var deferred = this.unresolvedSubscribes.get(sub.topicFilter);
              if (deferred) {
                this.unresolvedSubscribes["delete"](sub.topicFilter);
                deferred.resolve(packet);
              }
            }
          } else {
            throw new Error("received suback packet with unrecognized id " + packet.id);
          }
        };
        _proto3.handleUnsuback = function handleUnsuback(packet) {
          var _this6 = this;
          var unacknowledgedUnsubscribe = this.unacknowledgedUnsubscribes.get(packet.id);
          if (unacknowledgedUnsubscribe) {
            this.unacknowledgedUnsubscribes["delete"](packet.id);
            var _loop3 = function _loop3() {
              var sub = _step10.value;
              if (!sub) {
                return 1; // continue
              }

              sub.state = "unsubscribe-acknowledged";
              _this6.subscriptions = _this6.subscriptions.filter(function (s) {
                return s !== sub;
              });
              var deferred = _this6.unresolvedUnsubscribes.get(sub.topicFilter);
              if (deferred) {
                _this6.unresolvedUnsubscribes["delete"](sub.topicFilter);
                deferred.resolve(packet);
              }
            };
            for (var _iterator10 = _createForOfIteratorHelperLoose(unacknowledgedUnsubscribe.subscriptions), _step10; !(_step10 = _iterator10()).done;) {
              if (_loop3()) continue;
            }
          } else {
            throw new Error("received unsuback packet with unrecognized id " + packet.id);
          }
        };
        _proto3.startConnectTimer = function startConnectTimer() {
          var _this7 = this;
          this.startTimer("connect", function () {
            _this7.connectTimedOut();
          }, this.options.connectTimeout || defaultConnectTimeout);
        };
        _proto3.connectTimedOut = function connectTimedOut() {
          switch (this.connectionState) {
            case "connecting":
              break;
            default:
              throw new Error("connect timer should not be timing out in " + this.connectionState + " state");
          }
          this.changeState("offline");
          this.close();
          this.notifyConnectRejected(new Error("connect timed out"));
          this.reconnectAttempt = 0;
          this.startReconnectTimer();
        };
        _proto3.notifyConnectRejected = function notifyConnectRejected(err) {
          if (this.unresolvedConnect) {
            this.log("rejecting initial connect");
            this.unresolvedConnect.reject(err);
          }
        };
        _proto3.stopConnectTimer = function stopConnectTimer() {
          if (this.timerExists("connect")) {
            this.stopTimer("connect");
          }
        };
        _proto3.startReconnectTimer = function startReconnectTimer() {
          var _reconnectOptions$ret,
            _reconnectOptions$min,
            _reconnectOptions$max,
            _reconnectOptions$fac,
            _reconnectOptions$ran,
            _this8 = this;
          var options = this.options;
          var reconnectOptions;
          var defaultOptions;
          if (!this.everConnected) {
            reconnectOptions = options.connect || {};
            defaultOptions = defaultConnectOptions;
          } else {
            reconnectOptions = options.reconnect || {};
            defaultOptions = defaultReconnectOptions;
          }
          if (reconnectOptions === false) {
            return;
          } else if (reconnectOptions === true) {
            reconnectOptions = {};
          }
          var attempt = this.reconnectAttempt;
          var maxAttempts = (_reconnectOptions$ret = reconnectOptions.retries) != null ? _reconnectOptions$ret : defaultOptions.retries;
          if (attempt >= maxAttempts) {
            return false;
          }

          // I started off using the formula in this article
          // https://dthain.blogspot.com/2009/02/exponential-backoff-in-distributed.html
          // but modified the random part so that the delay will be strictly
          // increasing.
          var min = (_reconnectOptions$min = reconnectOptions.minDelay) != null ? _reconnectOptions$min : defaultOptions.minDelay;
          var max = (_reconnectOptions$max = reconnectOptions.maxDelay) != null ? _reconnectOptions$max : defaultOptions.maxDelay;
          var factor = (_reconnectOptions$fac = reconnectOptions.factor) != null ? _reconnectOptions$fac : defaultOptions.factor;
          var random = (_reconnectOptions$ran = reconnectOptions.random) != null ? _reconnectOptions$ran : defaultOptions.random;

          // The old way:
          // const randomness = 1 + (random ? Math.random() : 0);
          // const delay = Math.floor(Math.min(randomness * min * Math.pow(factor, attempt), max));

          // The new way:
          var thisDelay = min * Math.pow(factor, attempt);
          var nextDelay = min * Math.pow(factor, attempt + 1);
          var diff = nextDelay - thisDelay;
          var randomness = random ? diff * Math.random() : 0;
          var delay = Math.floor(Math.min(thisDelay + randomness, max));
          this.log("reconnect attempt " + (attempt + 1) + " in " + delay + "ms");
          this.startTimer("reconnect", function () {
            _this8.reconnectAttempt++;
            _this8.openConnection();
          }, delay);
          return true;
        };
        _proto3.stopReconnectTimer = function stopReconnectTimer() {
          if (this.timerExists("reconnect")) {
            this.stopTimer("reconnect");
          }
        };
        _proto3.startKeepAliveTimer = function startKeepAliveTimer() {
          var _this9 = this;
          if (!this.keepAlive) {
            return;
          }

          // This method doesn't get called until after sending the connect packet
          // so this.lastPacketTime should have a value.
          var elapsed = Date.now() - this.lastPacketTime.getTime();
          var timeout = this.keepAlive * 1000 - elapsed;
          this.startTimer("keepAlive", function () {
            return _this9.sendKeepAlive();
          }, timeout);
        };
        _proto3.stopKeepAliveTimer = function stopKeepAliveTimer() {
          if (this.timerExists("keepAlive")) {
            this.stopTimer("keepAlive");
          }
        };
        _proto3.sendKeepAlive = /*#__PURE__*/function () {
          var _sendKeepAlive = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee16() {
            var elapsed, timeout;
            return _regeneratorRuntime().wrap(function _callee16$(_context18) {
              while (1) switch (_context18.prev = _context18.next) {
                case 0:
                  if (!(this.connectionState === "connected")) {
                    _context18.next = 9;
                    break;
                  }
                  elapsed = Date.now() - this.lastPacketTime.getTime();
                  timeout = this.keepAlive * 1000;
                  if (!(elapsed >= timeout)) {
                    _context18.next = 6;
                    break;
                  }
                  _context18.next = 6;
                  return this.send({
                    type: "pingreq"
                  }, encode$9);
                case 6:
                  this.startKeepAliveTimer();
                  _context18.next = 10;
                  break;
                case 9:
                  this.log("keepAliveTimer should have been cancelled");
                case 10:
                case "end":
                  return _context18.stop();
              }
            }, _callee16, this);
          }));
          function sendKeepAlive() {
            return _sendKeepAlive.apply(this, arguments);
          }
          return sendKeepAlive;
        }();
        _proto3.stopTimers = function stopTimers() {
          this.stopConnectTimer();
          this.stopReconnectTimer();
          this.stopKeepAliveTimer();
        };
        _proto3.startTimer = function startTimer(name, cb, delay) {
          var _this10 = this;
          if (this.timerExists(name)) {
            this.log("timer " + name + " already exists");
            this.stopTimer(name);
          }
          this.log("starting timer " + name + " for " + delay + "ms");
          this.timers[name] = setTimeout(function () {
            delete _this10.timers[name];
            _this10.log("invoking timer " + name + " callback");
            cb();
          }, delay);
        };
        _proto3.stopTimer = function stopTimer(name) {
          if (!this.timerExists(name)) {
            this.log("no timer " + name + " to stop");
            return;
          }
          this.log("stopping timer " + name);
          var id = this.timers[name];
          if (id) {
            clearTimeout(id);
            delete this.timers[name];
          }
        };
        _proto3.timerExists = function timerExists(name) {
          return !!this.timers[name];
        }

        // Utility methods
        ;

        _proto3.changeState = function changeState(newState) {
          var oldState = this.connectionState;
          this.connectionState = newState;
          this.log("connectionState: " + oldState + " -> " + newState);
          this.emit("statechange", {
            from: oldState,
            to: newState
          });
          this.emit(newState);
        };
        _proto3.generateClientId = function generateClientId() {
          var clientId;
          if (typeof this.options.clientId === "string") {
            clientId = this.options.clientId;
          } else if (typeof this.options.clientId === "function") {
            clientId = this.options.clientId();
          } else {
            var prefix = this.options.clientIdPrefix || defaultClientIdPrefix;
            var suffix = Math.random().toString(36).slice(2);
            clientId = prefix + "-" + suffix;
          }
          return clientId;
        };
        _proto3.getURL = function getURL() {
          var url = typeof this.options.url === "function" ? this.options.url() : this.options.url;
          if (!url) {
            url = this.getDefaultURL();
          }
          if (typeof url === "string") {
            url = this.parseURL(url);
          }
          var protocol = url.protocol.slice(0, -1);
          if (!url.port) {
            url.port = defaultPorts[protocol].toString();
          }
          this.validateURL(url);
          return url;
        };
        _proto3.parseURL = function parseURL(url) {
          var parsed = new URL(url);

          // When Deno and browsers parse "mqtt:" URLs, they return "//host:port/path"
          // in the `pathname` property and leave `host`, `hostname`, and `port`
          // blank. This works around that by re-parsing as an "http:" URL and then
          // changing the protocol back to "mqtt:". Node doesn't behave like this.
          if (!parsed.hostname && parsed.pathname.startsWith("//")) {
            var _protocol = parsed.protocol;
            parsed = new URL(url.replace(_protocol, "http:"));
            parsed.protocol = _protocol;
          }
          return parsed;
        };
        _proto3.nextPacketId = function nextPacketId() {
          this.lastPacketId = (this.lastPacketId + 1) % packetIdLimit;

          // Don't allow packet id to be 0.
          if (!this.lastPacketId) {
            this.lastPacketId = 1;
          }
          return this.lastPacketId;
        };
        _proto3.send = /*#__PURE__*/function () {
          var _send = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee17(packet, encoder) {
            var bytes;
            return _regeneratorRuntime().wrap(function _callee17$(_context19) {
              while (1) switch (_context19.prev = _context19.next) {
                case 0:
                  this.log("sending " + packet.type + " packet", packet);
                  this.emit("packetsend", packet);
                  bytes = encoder(packet, this.utf8Encoder);
                  this.emit("bytessent", bytes);
                  _context19.next = 6;
                  return this.write(bytes);
                case 6:
                  this.lastPacketTime = new Date();
                case 7:
                case "end":
                  return _context19.stop();
              }
            }, _callee17, this);
          }));
          function send(_x10, _x11) {
            return _send.apply(this, arguments);
          }
          return send;
        }();
        _proto3.on = function on(eventName, listener) {
          var listeners = this.eventListeners.get(eventName);
          if (!listeners) {
            listeners = [];
            this.eventListeners.set(eventName, listeners);
          }
          listeners.push(listener);
        };
        _proto3.off = function off(eventName, listener) {
          var listeners = this.eventListeners.get(eventName);
          if (listeners) {
            this.eventListeners.set(eventName, listeners.filter(function (l) {
              return l !== listener;
            }));
          }
        };
        _proto3.emit = function emit(eventName) {
          var listeners = this.eventListeners.get(eventName);
          if (listeners) {
            for (var _len3 = arguments.length, args = new Array(_len3 > 1 ? _len3 - 1 : 0), _key3 = 1; _key3 < _len3; _key3++) {
              args[_key3 - 1] = arguments[_key3];
            }
            for (var _iterator11 = _createForOfIteratorHelperLoose(listeners), _step11; !(_step11 = _iterator11()).done;) {
              var listener = _step11.value;
              listener.apply(void 0, args);
            }
          }
        };
        return Client;
      }());
      var Deferred = function Deferred() {
        var _this11 = this;
        this.promise = void 0;
        this.resolve = void 0;
        this.reject = void 0;
        this.promise = new Promise(function (resolve, reject) {
          _this11.resolve = resolve;
          _this11.reject = reject;
        });
      };
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/base64url.ts", ['cc', './buffer_utils.ts'], function (exports) {
  var cclegacy, encoder;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      encoder = module.encoder;
    }],
    execute: function () {
      cclegacy._RF.push({}, "612e8BkpCVK8agEyWh2Jbgh", "base64url", undefined);
      var encodeBase64 = exports('encodeBase64', function encodeBase64(input) {
        var unencoded = input;
        if (typeof unencoded === 'string') {
          unencoded = encoder.encode(unencoded);
        }
        var CHUNK_SIZE = 0x8000;
        var arr = [];
        for (var i = 0; i < unencoded.length; i += CHUNK_SIZE) {
          // @ts-ignore
          arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
        }
        return btoa(arr.join(''));
      });
      var encode = exports('encode', function encode(input) {
        return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      });

      // export const decodeBase64 = (encoded: string): Uint8Array => {
      //   const binary = atob(encoded)
      //   const bytes = new Uint8Array(binary.length)
      //   for (let i = 0; i < binary.length; i++) {
      //     bytes[i] = binary.charCodeAt(i)
      //   }
      //   return bytes
      // }

      // export const decode = (input: Uint8Array | string) => {
      //   let encoded = input
      //   if (encoded instanceof Uint8Array) {
      //     encoded = decoder.decode(encoded)
      //   }
      //   encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '')
      //   try {
      //     return decodeBase64(encoded)
      //   } catch {
      //     throw new TypeError('The input to be decoded is not correctly encoded.')
      //   }
      // }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BaseComponent.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BasicEnum.ts', './CommonValue.ts', './EventMng.ts'], function (exports) {
  var _inheritsLoose, _asyncToGenerator, _regeneratorRuntime, cclegacy, _decorator, UIOpacity, Vec3, Component, BasicEnum, Platform, CommonValue, EventMng, NotificationType;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      UIOpacity = module.UIOpacity;
      Vec3 = module.Vec3;
      Component = module.Component;
    }, function (module) {
      BasicEnum = module.BasicEnum;
      Platform = module.Platform;
    }, function (module) {
      CommonValue = module.default;
    }, function (module) {
      EventMng = module.default;
      NotificationType = module.NotificationType;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "6fb02Z/BaVJV6omtXKATJ+o", "BaseComponent", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BaseComponent = exports('default', (_dec = ccclass('BaseComponent'), _dec(_class = /*#__PURE__*/function (_Component) {
        _inheritsLoose(BaseComponent, _Component);
        function BaseComponent() {
          var _this;
          _this = _Component.call(this) || this;
          _this.inter = void 0;
          _this.delayTime = void 0;
          _this.zIndex = void 0;
          _this.isLoadInit = false;
          _this.isStartInit = false;
          _this.orientationSprite = void 0;
          return _this;
        }
        var _proto = BaseComponent.prototype;
        _proto.onLoad = function onLoad() {
          if (this.getComponent(UIOpacity)) this.getComponent(UIOpacity).opacity = 255;
          this.setEvent(BasicEnum.OrientationChange, this.orientationEvent);
          this.isLoadInit = true;
        };
        _proto.start = function start() {
          this.isStartInit = true;
          this.orientationEvent(CommonValue.platform == Platform.Web);
        };
        _proto.setZIndex = function setZIndex() {
          this.node.setSiblingIndex(this.zIndex);
        };
        _proto.setLanguage = function setLanguage() {};
        _proto.personalComputerInit = function personalComputerInit() {
          this.node.setPosition(Vec3.ZERO);
          this.node.setScale(Vec3.ONE);
        };
        _proto.setEvent = function setEvent(name, callback) {
          EventMng.getInstance.setEvent(NotificationType.Basic, name, callback, this);
        };
        _proto.eventEmit = function eventEmit(name) {
          var _EventMng$getInstance;
          for (var _len = arguments.length, any = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
            any[_key - 1] = arguments[_key];
          }
          (_EventMng$getInstance = EventMng.getInstance).emit.apply(_EventMng$getInstance, [NotificationType.Basic, name].concat(any));
        };
        _proto.deletEvent = function deletEvent(name, callback) {
          EventMng.getInstance.deletEvent(NotificationType.Basic, name, callback, this);
        };
        _proto.show = /*#__PURE__*/function () {
          var _show = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
            var _this2 = this;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  if (!(!this.isLoadInit || !this.isStartInit)) {
                    _context.next = 3;
                    break;
                  }
                  _context.next = 3;
                  return new Promise(function (resolve, reject) {
                    var loop = setInterval(function () {
                      if (!_this2.isLoadInit) return;
                      clearInterval(loop);
                      resolve();
                    }, 16);
                  });
                case 3:
                  this.node.active = true;
                case 4:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function show() {
            return _show.apply(this, arguments);
          }
          return show;
        }();
        _proto.hide = function hide() {
          this.node.active = false;
        };
        _proto.startDelay = function startDelay() {
          var _this3 = this;
          this.delayTime = 0;
          this.inter = setInterval(function () {
            _this3.delayTime += 0.016;
          }, 0.016);
        };
        _proto.stopDelay = function stopDelay() {
          clearInterval(this.inter);
          return this.delayTime;
        };
        _proto.orientationEvent = function orientationEvent(isLandscape) {};
        return BaseComponent;
      }(Component)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BaseSingleton.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './SingletonManger.ts'], function (exports) {
  var _createClass, cclegacy, SingletManager;
  return {
    setters: [function (module) {
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      SingletManager = module.default;
    }],
    execute: function () {
      exports('default', BaseSingleton);
      cclegacy._RF.push({}, "6a397t9NcpOlKNL/HdE9kLZ", "BaseSingleton", undefined);
      function BaseSingleton() {
        var BaseSingleton = /*#__PURE__*/function () {
          function BaseSingleton() {}

          /**
           * 清除單例物件
           */
          var _proto = BaseSingleton.prototype;
          _proto.clear = function clear() {
            this._instance = null;
          };
          _createClass(BaseSingleton, null, [{
            key: "getInstance",
            get: function get() {
              if (!this.instance) {
                this.instance = new this();
                if (this.name != "SingletManager") {
                  SingletManager.instance.set(this.instance);
                } else {
                  var singletManager = this.instance;
                  singletManager.set(this.instance);
                }
              }
              return this.instance;
            }
          }]);
          return BaseSingleton;
        }();
        BaseSingleton.instance = void 0;
        return BaseSingleton;
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BaseSingletonComponent.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './SingletonManger.ts', './BaseComponent.ts'], function (exports) {
  var _inheritsLoose, _createClass, cclegacy, js, SingletManager, BaseComponent;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      js = module.js;
    }, function (module) {
      SingletManager = module.default;
    }, function (module) {
      BaseComponent = module.default;
    }],
    execute: function () {
      exports('default', BaseSingletonComponent);
      cclegacy._RF.push({}, "9aff1mvQxJDELM4V32eJIEC", "BaseSingletonComponent", undefined);
      function BaseSingletonComponent() {
        var BaseSingletonComponent = /*#__PURE__*/function (_BaseComponent) {
          _inheritsLoose(BaseSingletonComponent, _BaseComponent);
          function BaseSingletonComponent() {
            return _BaseComponent.apply(this, arguments) || this;
          }
          var _proto = BaseSingletonComponent.prototype;
          _proto.onLoad = function onLoad() {
            _BaseComponent.prototype.onLoad.call(this);
            SingletManager.instance.set(this);
            console.log(SingletManager.instance);
          }

          /**
           * 清除單例物件
           */;
          _proto.clear = function clear() {};
          _proto.onDestroy = function onDestroy() {
            _BaseComponent.prototype.onDestroy.call(this);
            console.log(js.getClassName(this));
            SingletManager.instance["delete"](js.getClassName(this));
          };
          _createClass(BaseSingletonComponent, null, [{
            key: "instance",
            get: function get() {
              if (!SingletManager.instance.get(js.getClassName(this))) ;
              return SingletManager.instance.get(js.getClassName(this));
            }
          }]);
          return BaseSingletonComponent;
        }(BaseComponent);
        return BaseSingletonComponent;
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicAutoPlay.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './Public.ts', './BasicEnum.ts', './CustomEvent.ts', './LabelButton.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, BaseComponent, setFunctionName, Plug, BasicEnum, CustomEvent, CEType, LabelButton;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      setFunctionName = module.setFunctionName;
      Plug = module.Plug;
    }, function (module) {
      BasicEnum = module.BasicEnum;
    }, function (module) {
      CustomEvent = module.default;
      CEType = module.CEType;
    }, function (module) {
      LabelButton = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "b50e3CfPnNBvqZPxQaPwuH1", "BasicAutoPlay", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BasicAutoPlay = exports('default', (_dec = ccclass('BasicAutoPlay'), _dec2 = property({
        type: LabelButton,
        tooltip: "全部局數按鈕"
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(BasicAutoPlay, _BaseComponent);
        function BasicAutoPlay() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          //TODO 可最佳化處
          /**
           * 之後可以用成動態生成
           */
          _initializerDefineProperty(_this, "items", _descriptor, _assertThisInitialized(_this));
          _this.roundDate = ["10", "20", "30", "50", "♾️"];
          _this.selectIndex = void 0;
          _this.selectBet = void 0;
          return _this;
        }
        var _proto = BasicAutoPlay.prototype;
        _proto.onLoad = function onLoad() {
          this.setEvent(BasicEnum.OpenAutoPlay, this.show);
          for (var index = 0; index < this.items.length; index++) {
            this.items[index].label.string = this.roundDate[index];
            CustomEvent.addEvent(CEType.ClickEvents, this, Plug.Model.getFunctionName(this.onSelectIndex), this.items[index], this.roundDate[index]);
          }
          _BaseComponent.prototype.onLoad.call(this);
        };
        _proto.start = function start() {
          this.selectIndex = this.roundDate[0];
          //因為初始時需要隱藏
          this.hide();
          _BaseComponent.prototype.start.call(this);
        };
        _proto.onSelectIndex = function onSelectIndex(e, customEventData) {
          this.selectIndex = customEventData;
        };
        _proto.onSetAutoPlay = function onSetAutoPlay(e, customEventData) {
          this.eventEmit(BasicEnum.SetAutoPlay, this.selectIndex);
          this.eventEmit(BasicEnum.StartAutoPlay, null, this.selectBet);
          this.hide();
        };
        return BasicAutoPlay;
      }(BaseComponent), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "items", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return [];
        }
      }), _applyDecoratedDescriptor(_class2.prototype, "onSelectIndex", [setFunctionName], Object.getOwnPropertyDescriptor(_class2.prototype, "onSelectIndex"), _class2.prototype)), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicBetInfo.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './Public.ts', './BasicEnum.ts', './CommonValue.ts', './SpriteButton.ts', './CustomEvent.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Button, Sprite, Label, Tween, Vec3, tween, v3, BaseComponent, setFunctionName, Plug, BasicEnum, BasicTweenTag, CommonValue, SpriteButton, CustomEvent, CEType;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Button = module.Button;
      Sprite = module.Sprite;
      Label = module.Label;
      Tween = module.Tween;
      Vec3 = module.Vec3;
      tween = module.tween;
      v3 = module.v3;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      setFunctionName = module.setFunctionName;
      Plug = module.Plug;
    }, function (module) {
      BasicEnum = module.BasicEnum;
      BasicTweenTag = module.BasicTweenTag;
    }, function (module) {
      CommonValue = module.default;
    }, function (module) {
      SpriteButton = module.default;
    }, function (module) {
      CustomEvent = module.default;
      CEType = module.CEType;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _dec5, _dec6, _dec7, _dec8, _dec9, _class, _class2, _descriptor, _descriptor2, _descriptor3, _descriptor4, _descriptor5, _descriptor6, _descriptor7, _descriptor8, _descriptor9;
      cclegacy._RF.push({}, "97ef12IUwhE1brJPYN3Q69N", "BasicBetInfo", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BasicBetInfo = exports('default', (_dec = ccclass('BasicBetInfo'), _dec2 = property({
        type: SpriteButton,
        tooltip: "快速按鈕"
      }), _dec3 = property({
        type: Button,
        tooltip: "減號按鈕"
      }), _dec4 = property({
        type: Button,
        tooltip: "加號按鈕"
      }), _dec5 = property({
        type: Button,
        tooltip: "開啟下注介面按鈕"
      }), _dec6 = property({
        type: Sprite,
        tooltip: "下注額背景"
      }), _dec7 = property({
        type: Label,
        tooltip: "下注額"
      }), _dec8 = property({
        type: Button,
        tooltip: "自動背景"
      }), _dec9 = property({
        type: Label,
        tooltip: "自動數字"
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(BasicBetInfo, _BaseComponent);
        function BasicBetInfo() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          //Bet相關按鈕
          _initializerDefineProperty(_this, "btnTurbo", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "btnMinus", _descriptor2, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "btnPlus", _descriptor3, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "btnAutoPlay", _descriptor4, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "spriteTotalBg", _descriptor5, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "labelTotalBet", _descriptor6, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "btnAutoPlayIng", _descriptor7, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "labelAutoCount", _descriptor8, _assertThisInitialized(_this));
          //TODO 多少投注的量由Server決定
          _this.betArr = [1, 5, 25, 100, 500, 2000, 5000, 10000, 25000, 50000];
          //TODO 上限值誰決定
          _this.maxBet = 100000;
          _this.betIndex = 1;
          _this.currentBet = 0;
          _this.canPlayGame = false;
          _this.countAutoPlay = void 0;
          _initializerDefineProperty(_this, "turboSpeed", _descriptor9, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = BasicBetInfo.prototype;
        _proto.onLoad = function onLoad() {
          this.setEvent(BasicEnum.EnabledPlay, this.enabledPlay);
          this.setEvent(BasicEnum.SetChipIndex, this.onChangeBetIndex);
          this.setEvent(BasicEnum.SetAutoPlay, this.setAutoPlay);
          this.setEvent(BasicEnum.UpdateAutoRound, this.updateAutoPlay);
          CustomEvent.addEvent(CEType.ClickEvents, this, Plug.Model.getFunctionName(this.onChangeTurboLevel), this.btnTurbo);
          CustomEvent.addEvent(CEType.ClickEvents, this, Plug.Model.getFunctionName(this.onOpenAutoPlay), this.btnAutoPlay);
          CustomEvent.addEvent(CEType.ClickEvents, this, Plug.Model.getFunctionName(this.onBetPlus), this.btnPlus);
          CustomEvent.addEvent(CEType.ClickEvents, this, Plug.Model.getFunctionName(this.onBetMinus), this.btnMinus);
          CustomEvent.addEvent(CEType.ClickEvents, this, Plug.Model.getFunctionName(this.onCloseAutoPlay), this.btnAutoPlayIng);
          _BaseComponent.prototype.onLoad.call(this);
        };
        _proto.start = function start() {
          this.initBet();
          CommonValue.turboLevel = -1;
          this.onChangeTurboLevel();
          this.btnTurbo.updateSpriteStatus();
          _BaseComponent.prototype.start.call(this);
        };
        _proto.initBet = function initBet() {
          CommonValue.isTurbo = false;
          this.onChangeBetIndex(1);
          this.updateBetText();
          this.btnTurbo.initStatus(true, false);
          this.canPlayGame = false;
          this.closeAuto();
        };
        _proto.onBetPlus = function onBetPlus(e, customEventData) {
          if (this.currentBet === this.maxBet) return;
          this.currentBet += this.betArr[this.betIndex];
          if (this.currentBet > this.maxBet) this.currentBet = this.maxBet;
          // if (!this.canPlayGame) {
          //     this.canPlayGame = true;
          //     this.eventEmit(BasicEnum.EnabledBet, true)
          // }
          this.updateBetText();
        };
        _proto.onBetMinus = function onBetMinus(e, customEventData) {
          if (this.currentBet === 0) return;
          this.currentBet -= this.betArr[this.betIndex];
          if (this.currentBet <= 1) {
            this.currentBet = 1;
            //要跟身上的錢包比較
            // if (this.canPlayGame) {
            //     this.canPlayGame = false;
            // this.eventEmit(BasicEnum.EnabledBet, false)
            // }
          }

          this.updateBetText();
        };
        _proto.onChangeTurboLevel = function onChangeTurboLevel(e, customEventData) {
          CommonValue.turboLevel++;
          Tween.stopAllByTag(BasicTweenTag.TurboRota);
          if (CommonValue.turboLevel > 2) CommonValue.turboLevel = 0;
          if (CommonValue.turboLevel == 0) {
            CommonValue.isTurbo = false;
            this.btnTurbo.node.eulerAngles = Vec3.ZERO;
          } else {
            CommonValue.isTurbo = true;
            tween(this.btnTurbo.node).tag(BasicTweenTag.TurboRota).repeatForever(tween().by(this.turboSpeed / CommonValue.turboLevel, {
              eulerAngles: v3(0, 0, -360)
            })).start();
          }
          this.btnTurbo.isSelect = CommonValue.isTurbo;
        };
        _proto.onOpenAutoPlay = function onOpenAutoPlay(e, customEventData) {
          this.eventEmit(BasicEnum.OpenAutoPlay, true);
        };
        _proto.onChangeBetIndex = function onChangeBetIndex(index) {
          if (index > this.betArr.length || index == this.betArr.length) {
            console.error("超過arr範圍");
            return;
          }
          if (isNaN(Number(index))) {
            console.error("非法值");
            return;
          }
          this.betIndex = Number(index);
          this.currentBet = this.betArr[index];
          this.updateBetText();
        };
        _proto.onCloseAutoPlay = function onCloseAutoPlay(e, customEventData) {
          this.btnAutoPlay.node.active = true;
          CommonValue.isAuto = false;
          this.closeAuto();
        };
        _proto.enabledPlay = function enabledPlay(bool) {
          this.btnPlus.interactable = bool;
          this.btnMinus.interactable = bool;
        };
        _proto.updateBetText = function updateBetText() {
          this.labelTotalBet.string = Intl.NumberFormat().format(this.currentBet).toString();
        };
        _proto.setAutoPlay = function setAutoPlay(count) {
          this.btnAutoPlay.node.active = false;
          this.closeAuto();
          this.btnAutoPlayIng.node.active = true;
          this.labelAutoCount.node.active = true;
          this.labelAutoCount.string = count;
          this.countAutoPlay = Number(count);
          CommonValue.isAuto = true;
        };
        _proto.updateAutoPlay = function updateAutoPlay() {
          if (!isNaN(this.countAutoPlay)) {
            this.countAutoPlay--;
            if (this.countAutoPlay < 1) {
              CommonValue.isAuto = false;
              this.btnAutoPlay.node.active = true;
              this.closeAuto();
            } else this.labelAutoCount.string = this.countAutoPlay.toString();
          }
        };
        _proto.closeAuto = function closeAuto() {
          this.countAutoPlay = -1;
          this.btnAutoPlayIng.node.active = false;
          this.labelAutoCount.node.active = false;
        };
        return BasicBetInfo;
      }(BaseComponent), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "btnTurbo", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "btnMinus", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "btnPlus", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor4 = _applyDecoratedDescriptor(_class2.prototype, "btnAutoPlay", [_dec5], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor5 = _applyDecoratedDescriptor(_class2.prototype, "spriteTotalBg", [_dec6], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor6 = _applyDecoratedDescriptor(_class2.prototype, "labelTotalBet", [_dec7], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor7 = _applyDecoratedDescriptor(_class2.prototype, "btnAutoPlayIng", [_dec8], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor8 = _applyDecoratedDescriptor(_class2.prototype, "labelAutoCount", [_dec9], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor9 = _applyDecoratedDescriptor(_class2.prototype, "turboSpeed", [property], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return 1;
        }
      }), _applyDecoratedDescriptor(_class2.prototype, "onBetPlus", [setFunctionName], Object.getOwnPropertyDescriptor(_class2.prototype, "onBetPlus"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "onBetMinus", [setFunctionName], Object.getOwnPropertyDescriptor(_class2.prototype, "onBetMinus"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "onChangeTurboLevel", [setFunctionName], Object.getOwnPropertyDescriptor(_class2.prototype, "onChangeTurboLevel"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "onOpenAutoPlay", [setFunctionName], Object.getOwnPropertyDescriptor(_class2.prototype, "onOpenAutoPlay"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "onCloseAutoPlay", [setFunctionName], Object.getOwnPropertyDescriptor(_class2.prototype, "onCloseAutoPlay"), _class2.prototype)), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicChip.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './EasyCode.ts', './Public.ts', './BasicEnum.ts', './CustomEvent.ts', './LabelButton.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _asyncToGenerator, _regeneratorRuntime, cclegacy, _decorator, Prefab, Node, instantiate, find, Label, UITransform, Sprite, resources, SpriteFrame, BaseComponent, EasyCode, setFunctionName, Plug, BasicEnum, CustomEvent, CEType, LabelButton;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Prefab = module.Prefab;
      Node = module.Node;
      instantiate = module.instantiate;
      find = module.find;
      Label = module.Label;
      UITransform = module.UITransform;
      Sprite = module.Sprite;
      resources = module.resources;
      SpriteFrame = module.SpriteFrame;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      EasyCode = module.default;
    }, function (module) {
      setFunctionName = module.setFunctionName;
      Plug = module.Plug;
    }, function (module) {
      BasicEnum = module.BasicEnum;
    }, function (module) {
      CustomEvent = module.default;
      CEType = module.CEType;
    }, function (module) {
      LabelButton = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _class2, _class3, _descriptor, _descriptor2, _descriptor3;
      cclegacy._RF.push({}, "84c91txiBNM1JTzEwP1UsjV", "BasicChip", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BasicChip = exports('default', (_dec = ccclass('BasicChip'), _dec2 = property({
        type: Prefab,
        tooltip: "籌碼物件"
      }), _dec3 = property({
        type: Node,
        tooltip: "籌碼放置位置"
      }), _dec4 = property(Node), _dec(_class2 = (_class3 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(BasicChip, _BaseComponent);
        function BasicChip() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          // chipInfo: number[] = [1, 5, 25, 100, 500, 2000, 5000, 10000, 25000,50000]
          _this.deskTopChipInfo = [1, 5, 25, 100, 500, 2000, 5000, 10000, 25000];
          _this.mobileChipInfo = [1, 5, 25, 100, 500, 2000, 5000];
          _initializerDefineProperty(_this, "item", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "layoutChip", _descriptor2, _assertThisInitialized(_this));
          _this.mapChip = new Map();
          _initializerDefineProperty(_this, "conLabel", _descriptor3, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = BasicChip.prototype;
        _proto.onLoad = function onLoad() {
          this.setEvent(BasicEnum.EnabledPlay, this.changeAllChipStatus);
          _BaseComponent.prototype.onLoad.call(this);
        };
        _proto.start = /*#__PURE__*/function () {
          var _start = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  _context.next = 2;
                  return this.initChip();
                case 2:
                  _BaseComponent.prototype.start.call(this);
                case 3:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function start() {
            return _start.apply(this, arguments);
          }
          return start;
        }();
        _proto.changeAllChipStatus = function changeAllChipStatus(bool) {
          this.mapChip.forEach(function (chip) {
            chip.btn.interactable = bool;
          });
        };
        _proto.initChip = /*#__PURE__*/function () {
          var _initChip = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee3() {
            var _this2 = this;
            return _regeneratorRuntime().wrap(function _callee3$(_context3) {
              while (1) switch (_context3.prev = _context3.next) {
                case 0:
                  return _context3.abrupt("return", new Promise( /*#__PURE__*/_asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee2(resolve, reject) {
                    var startTime, spriteFrames, GetToLenDate, i, _chipNode, easy;
                    return _regeneratorRuntime().wrap(function _callee2$(_context2) {
                      while (1) switch (_context2.prev = _context2.next) {
                        case 0:
                          startTime = Date.now(); // 開始計時
                          _context2.prev = 1;
                          console.log("Chip開始載入資源...");
                          // 載入資源
                          _context2.next = 5;
                          return new Promise(function (resolve, reject) {
                            resources.loadDir("Common/Sprite/Chip", SpriteFrame, function (err, loadedFrames) {
                              if (err) {
                                reject(err);
                              } else {
                                resolve(loadedFrames);
                              }
                            });
                          });
                        case 5:
                          spriteFrames = _context2.sent;
                          // 因為只有兩種狀態
                          // 初始化按鈕元件並設置 SpriteFrame
                          GetToLenDate = _this2.deskTopChipInfo.length > _this2.mobileChipInfo.length ? _this2.deskTopChipInfo : _this2.mobileChipInfo;
                          for (i = 0; i < GetToLenDate.length; i++) {
                            _chipNode = instantiate(_this2.item);
                            _chipNode.parent = _this2.layoutChip;
                            _this2.mapChip.set(i, new ChipBind(_chipNode.getComponent(LabelButton), find("Label", _chipNode).getComponent(Label), _chipNode.getComponent(UITransform)));
                          }
                          easy = new EasyCode();
                          spriteFrames.forEach(function (spriteFrame) {
                            var _spriteFrame$name$spl = spriteFrame.name.split("_"),
                              type = _spriteFrame$name$spl[0],
                              numStr = _spriteFrame$name$spl[1];
                            var num = Number(numStr);
                            if (!_this2.mapChip.has(num)) return;
                            var chip = _this2.mapChip.get(num);
                            if (!chip.btn) return; // 確保有對應的按鈕
                            easy.autoFollow(chip.label.node, _this2.conLabel);
                            if (type.includes('ChipPress')) {
                              chip.btn.pressedSprite = spriteFrame;
                            } else if (type.includes('Chip')) {
                              chip.btn.normalSprite = spriteFrame;
                            }
                            chip.bgSprite.sizeMode = Sprite.SizeMode.CUSTOM;
                            CustomEvent.addEvent(CEType.ClickEvents, _this2, Plug.Model.getFunctionName(_this2.selectChip), chip.btn, numStr);
                            chip.label.string = Plug.PublicModel.getInstance.changeKMB(GetToLenDate[num]);
                          });
                          console.log("\u5B8C\u6210\u6240\u6709\u64CD\u4F5C\uFF01\u7E3D\u8017\u6642\uFF1A" + (Date.now() - startTime) + " ms");
                          resolve();
                          _context2.next = 16;
                          break;
                        case 14:
                          _context2.prev = 14;
                          _context2.t0 = _context2["catch"](1);
                        case 16:
                        case "end":
                          return _context2.stop();
                      }
                    }, _callee2, null, [[1, 14]]);
                  }))));
                case 1:
                case "end":
                  return _context3.stop();
              }
            }, _callee3);
          }));
          function initChip() {
            return _initChip.apply(this, arguments);
          }
          return initChip;
        }();
        _proto.selectChip = function selectChip(e, customEventData) {
          // console.warn(customEventData);
          this.eventEmit(BasicEnum.SetChipIndex, Number(customEventData));
        };
        return BasicChip;
      }(BaseComponent), (_descriptor = _applyDecoratedDescriptor(_class3.prototype, "item", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class3.prototype, "layoutChip", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor3 = _applyDecoratedDescriptor(_class3.prototype, "conLabel", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _applyDecoratedDescriptor(_class3.prototype, "selectChip", [setFunctionName], Object.getOwnPropertyDescriptor(_class3.prototype, "selectChip"), _class3.prototype)), _class3)) || _class2));
      var ChipBind = function ChipBind(_btn, _label, _ui) {
        this.bgSprite = void 0;
        this.btn = void 0;
        this.label = void 0;
        this.ui = void 0;
        this.btn = _btn;
        this.label = _label;
        this.ui = _ui;
        this.bgSprite = _btn.target.getComponent(Sprite);
      };
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicEnum.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "4c6f2B5ZVdN2LqVN0DmZZRd", "BasicEnum", undefined);
      var BasicEnum = exports('BasicEnum', /*#__PURE__*/function (BasicEnum) {
        BasicEnum[BasicEnum["SetChipIndex"] = 0] = "SetChipIndex";
        BasicEnum[BasicEnum["OrientationChange"] = 1] = "OrientationChange";
        BasicEnum[BasicEnum["SendAPI"] = 2] = "SendAPI";
        BasicEnum[BasicEnum["Result"] = 3] = "Result";
        BasicEnum[BasicEnum["ShowWinEnd"] = 4] = "ShowWinEnd";
        BasicEnum[BasicEnum["EnabledPlay"] = 5] = "EnabledPlay";
        BasicEnum[BasicEnum["EnabledBet"] = 6] = "EnabledBet";
        BasicEnum[BasicEnum["OpenAutoPlay"] = 7] = "OpenAutoPlay";
        BasicEnum[BasicEnum["SetAutoPlay"] = 8] = "SetAutoPlay";
        BasicEnum[BasicEnum["StartAutoPlay"] = 9] = "StartAutoPlay";
        BasicEnum[BasicEnum["UpdateAutoRound"] = 10] = "UpdateAutoRound";
        return BasicEnum;
      }({}));
      var BasicTweenTag = exports('BasicTweenTag', {
        TurboRota: 0
      });
      var Platform = exports('Platform', /*#__PURE__*/function (Platform) {
        Platform["Web"] = "web";
        Platform["Mobile"] = "mobile";
        return Platform;
      }({}));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicGameShow.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './BasicEnum.ts', './CommonValue.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, BaseComponent, BasicEnum, CommonValue;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      BasicEnum = module.BasicEnum;
    }, function (module) {
      CommonValue = module.default;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "f12e71vOilA9axkFCudBjJ7", "BasicGameShow", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BasicGameShow = exports('default', (_dec = ccclass('BasicGameShow'), _dec(_class = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(BasicGameShow, _BaseComponent);
        function BasicGameShow() {
          return _BaseComponent.apply(this, arguments) || this;
        }
        var _proto = BasicGameShow.prototype;
        _proto.onLoad = function onLoad() {
          this.setEvent(BasicEnum.Result, this.showWin);
          _BaseComponent.prototype.onLoad.call(this);
        };
        _proto.showWin = function showWin(result) {};
        _proto.endShow = function endShow() {
          //先確認是否有自動才釋放按鈕
          if (!CommonValue.isAuto) this.eventEmit(BasicEnum.EnabledPlay, true);
          //最終結果顯示完畢
          this.eventEmit(BasicEnum.ShowWinEnd);
        };
        return BasicGameShow;
      }(BaseComponent)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicPlaySelect.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './SpriteButton.ts', './BasicSelect.ts', './CommonValue.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, SpriteButton, BasicSelect, BasicSendDate, CommonValue;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      SpriteButton = module.default;
    }, function (module) {
      BasicSelect = module.default;
      BasicSendDate = module.BasicSendDate;
    }, function (module) {
      CommonValue = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "34c43nAsuJJ+Kauhl7hyBm7", "BasicPlaySelect", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      /**
       * 適用於只有單一下注Play按鈕的模式
       */
      var BasicPlaySelect = exports('default', (_dec = ccclass('BasicPlaySelect'), _dec2 = property({
        type: SpriteButton,
        tooltip: "Play下注按鈕"
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_BasicSelect) {
        _inheritsLoose(BasicPlaySelect, _BasicSelect);
        function BasicPlaySelect() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BasicSelect.call.apply(_BasicSelect, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "btnPlay", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = BasicPlaySelect.prototype;
        /**
         * superLoad需最後做
         */
        _proto.onLoad = function onLoad() {
          this.setBtnMap(Select, this.btnPlay, this.onSelect);
          _BasicSelect.prototype.onLoad.call(this);
        };
        _proto.start = function start() {
          this.btnPlay.initStatus(true, false);
          _BasicSelect.prototype.start.call(this);
        };
        _proto.enabledPlay = function enabledPlay(bool) {
          this.btnPlay.interactable = bool;
        }
        // protected loopGame(): void {
        //     super.loopGame()
        // }
        ;

        _proto.showWinEnd = function showWinEnd() {
          if (CommonValue.isAuto) return this.loopGame();
          this.getCompo(Select.Play).isSelect = false;
        };
        return BasicPlaySelect;
      }(BasicSelect), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "btnPlay", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _class2)) || _class));
      var Select = exports('Select', /*#__PURE__*/function (Select) {
        Select["Play"] = "Play";
        return Select;
      }({}));
      var BasicPlaySendDate = exports('BasicPlaySendDate', /*#__PURE__*/function (_BasicSendDate) {
        _inheritsLoose(BasicPlaySendDate, _BasicSendDate);
        function BasicPlaySendDate() {
          return _BasicSendDate.apply(this, arguments) || this;
        }
        return BasicPlaySendDate;
      }(BasicSendDate));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicRandomAutoPlay.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './Public.ts', './CustomEvent.ts', './SpriteButton.ts', './BasicAutoPlay.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, setFunctionName, Plug, CustomEvent, CEType, SpriteButton, BasicAutoPlay;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      setFunctionName = module.setFunctionName;
      Plug = module.Plug;
    }, function (module) {
      CustomEvent = module.default;
      CEType = module.CEType;
    }, function (module) {
      SpriteButton = module.default;
    }, function (module) {
      BasicAutoPlay = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "b60a2+GxdFBGYDwdjLA99Ut", "BasicRandomAutoPlay", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BasicRandomAutoPlay = exports('default', (_dec = ccclass('BasicRandomAutoPlay'), _dec2 = property({
        type: SpriteButton,
        tooltip: "隨機下注按鈕"
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_BasicAutoPlay) {
        _inheritsLoose(BasicRandomAutoPlay, _BasicAutoPlay);
        function BasicRandomAutoPlay() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BasicAutoPlay.call.apply(_BasicAutoPlay, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "btnRandom", _descriptor, _assertThisInitialized(_this));
          _this.mapAllBtn = new Map();
          _this.gameSelectEnum = void 0;
          return _this;
        }
        var _proto = BasicRandomAutoPlay.prototype;
        _proto.onLoad = function onLoad() {
          this.setBtnMap(Select, this.btnRandom, this.onSelectBet);
          _BasicAutoPlay.prototype.onLoad.call(this);
        };
        _proto.start = function start() {
          this.mapAllBtn.forEach(function (btn) {
            btn.initStatus(true, false);
          });
          //初始化時會優先量Random
          this.selectBet = Select.Random;
          this.changeBtnStatus(this.getCompo(this.selectBet), true);
          _BasicAutoPlay.prototype.start.call(this);
        };
        _proto.onSelectBet = function onSelectBet(e, customEventData) {
          //把上一個狀態取消
          if (!Plug.Model.checkStringNull(this.selectBet)) this.changeBtnStatus(this.getCompo(this.selectBet), false);
          this.changeBtnStatus(this.getCompo(customEventData), true);
          this.selectBet = customEventData;
        };
        _proto.getCompo = function getCompo(type) {
          if (!this.mapAllBtn.has(type)) throw new Error("\u7DE8\u8F2F\u5668node\u6A94\u6848\u547D\u540D\u6709\u554F\u984C\uFF0Ctype\u7269\u4EF6\u540D\u7A31\uFF1A" + type + "\uFF0C\u6B63\u78BA\u6027\u8ACB\u4F9D\u7167Select\u5B57\u4E32\u547D\u540D");
          return this.mapAllBtn.get(type);
        };
        _proto.changeBtnStatus = function changeBtnStatus(btn, isSelect) {
          btn.isSelect = isSelect;
          btn.updateSpriteStatus();
        };
        _proto.setBtnMap = function setBtnMap(enumType, btn, func) {
          var customEventData = btn.node.name.replace("btn", "");
          if (!Plug.Model.checkHasEnum(enumType, customEventData)) throw new Error("\u7DE8\u8F2F\u5668node\u6A94\u6848\u547D\u540D\u6709\u554F\u984C\uFF0Ctype\u7269\u4EF6\u540D\u7A31\uFF1A" + customEventData + "\uFF0C\u6B63\u78BA\u6027\u8ACB\u4F9D\u7167Select\u5B57\u4E32\u547D\u540D");
          CustomEvent.addEvent(CEType.ClickEvents, this, Plug.Model.getFunctionName(func), btn, customEventData);
          this.mapAllBtn.set(customEventData, btn);
        };
        return BasicRandomAutoPlay;
      }(BasicAutoPlay), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "btnRandom", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _applyDecoratedDescriptor(_class2.prototype, "onSelectBet", [setFunctionName], Object.getOwnPropertyDescriptor(_class2.prototype, "onSelectBet"), _class2.prototype)), _class2)) || _class));
      var Select = exports('Select', /*#__PURE__*/function (Select) {
        Select["Random"] = "Random";
        return Select;
      }({}));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicRandomSelect.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './CommonValue.ts', './SpriteButton.ts', './BasicSelect.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Label, random, CommonValue, SpriteButton, BasicSelect, BasicSendDate;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Label = module.Label;
      random = module.random;
    }, function (module) {
      CommonValue = module.default;
    }, function (module) {
      SpriteButton = module.default;
    }, function (module) {
      BasicSelect = module.default;
      BasicSendDate = module.BasicSendDate;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class2, _class3, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "4f76a7nn5FJZbBB3kbfpSKo", "BasicRandomSelect", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      /**
       * 適用於有Random按鈕模式，除了Random外的按鈕需要自行擴展，可參考M4 MiniGame
       */
      var BasicRandomSelect = exports('default', (_dec = ccclass('BasicRandomSelect'), _dec2 = property({
        type: SpriteButton,
        tooltip: "隨機下注按鈕"
      }), _dec3 = property({
        type: Label,
        tooltip: "隨機下注文字"
      }), _dec(_class2 = (_class3 = /*#__PURE__*/function (_BasicSelect) {
        _inheritsLoose(BasicRandomSelect, _BasicSelect);
        function BasicRandomSelect() {
          var _this2;
          for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
            args[_key2] = arguments[_key2];
          }
          _this2 = _BasicSelect.call.apply(_BasicSelect, [this].concat(args)) || this;
          _initializerDefineProperty(_this2, "btnRandom", _descriptor, _assertThisInitialized(_this2));
          _initializerDefineProperty(_this2, "labelRandom", _descriptor2, _assertThisInitialized(_this2));
          _this2.currentSelect = void 0;
          _this2.rememberDate = void 0;
          return _this2;
        }
        var _proto = BasicRandomSelect.prototype;
        /**
         * superLoad需最後做
         */
        _proto.onLoad = function onLoad() {
          this.setBtnMap(Select, this.btnRandom, this.onSelect);
          _BasicSelect.prototype.onLoad.call(this);
        };
        _proto.start = function start() {
          this.mapAllBtn.forEach(function (btn) {
            btn.initStatus(true, false);
          });
          _BasicSelect.prototype.start.call(this);
        };
        _proto.enabledPlay = function enabledPlay(bool) {
          this.mapAllBtn.forEach(function (btn) {
            btn.interactable = bool;
          });
        };
        _proto.showWinEnd = function showWinEnd() {
          if (CommonValue.isAuto) return this.loopGame();
          this.getCompo(this.currentSelect).isSelect = false;
          if (this.currentSelect == Select.Random) this.getCompo(this.rememberDate.select).isSelect = false;
        };
        _proto.randomSelect = function randomSelect() {
          var selectLen = this.gameSelectEnum.length;
          this.rememberDate.select = this.gameSelectEnum[Math.floor(random() * selectLen) % selectLen];
          this.changeBtnStatus(this.getCompo(this.rememberDate.select), true);
        };
        _proto.loopGame = function loopGame() {
          if (this.currentSelect == Select.Random) {
            this.changeBtnStatus(this.getCompo(this.rememberDate.select), false);
            this.randomSelect();
          }
          _BasicSelect.prototype.loopGame.call(this);
        };
        return BasicRandomSelect;
      }(BasicSelect), (_descriptor = _applyDecoratedDescriptor(_class3.prototype, "btnRandom", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class3.prototype, "labelRandom", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      })), _class3)) || _class2));
      var Select = exports('Select', /*#__PURE__*/function (Select) {
        Select["Random"] = "Random";
        return Select;
      }({}));
      var BasicRandomSendDate = exports('BasicRandomSendDate', /*#__PURE__*/function (_BasicSendDate) {
        _inheritsLoose(BasicRandomSendDate, _BasicSendDate);
        function BasicRandomSendDate() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BasicSendDate.call.apply(_BasicSendDate, [this].concat(args)) || this;
          _this.select = void 0;
          return _this;
        }
        return BasicRandomSendDate;
      }(BasicSendDate));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicSelect.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './Public.ts', './BasicEnum.ts', './CommonValue.ts', './CustomEvent.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, cclegacy, _decorator, BaseComponent, setFunctionName, Plug, BasicEnum, CommonValue, CustomEvent, CEType;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      setFunctionName = module.setFunctionName;
      Plug = module.Plug;
    }, function (module) {
      BasicEnum = module.BasicEnum;
    }, function (module) {
      CommonValue = module.default;
    }, function (module) {
      CustomEvent = module.default;
      CEType = module.CEType;
    }],
    execute: function () {
      var _dec, _class, _class2;
      cclegacy._RF.push({}, "69534l4JtRLB68Xd7TMtX+B", "BasicSelect", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BasicSelect = exports('default', (_dec = ccclass('BasicSelect'), _dec(_class = (_class2 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(BasicSelect, _BaseComponent);
        function BasicSelect() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          _this.rememberDate = void 0;
          _this.gameSelectEnum = void 0;
          _this.mapAllBtn = new Map();
          return _this;
        }
        var _proto = BasicSelect.prototype;
        /**
         * superLoad需最後做
         */
        _proto.onLoad = function onLoad() {
          this.setEvent(BasicEnum.ShowWinEnd, this.showWinEnd);
          this.setEvent(BasicEnum.EnabledPlay, this.enabledPlay);
          this.setEvent(BasicEnum.StartAutoPlay, this.onSelect);
          if (!this.gameSelectEnum) console.error("\u4F60\u5FD8\u8A18\u521D\u59CB\u5316selectEnum");
          _BaseComponent.prototype.onLoad.call(this);
        };
        _proto.start = function start() {
          _BaseComponent.prototype.start.call(this);
        };
        _proto.onSelect = function onSelect(e, customEventData) {
          this.eventEmit(BasicEnum.EnabledPlay, false);
          this.updateSelection(e, customEventData);
          this.PacketBuild();
          this.processGameFlow();
        };
        _proto.updateSelection = function updateSelection(e, customEventData) {};
        _proto.PacketBuild = function PacketBuild() {};
        _proto.processGameFlow = function processGameFlow() {
          this.eventEmit(BasicEnum.SendAPI, this.rememberDate);
        };
        _proto.loopGame = function loopGame() {
          /** 這邊流程必須注意，要先確認好當局是否要繼續auto，有繼續auto的話先送封包在扣局數 */
          CommonValue.isAuto && this.eventEmit(BasicEnum.SendAPI, this.rememberDate);
          this.eventEmit(BasicEnum.UpdateAutoRound);
        };
        _proto.enabledPlay = function enabledPlay(bool) {}
        /**更改按鈕選擇狀態 */;
        _proto.changeBtnStatus = function changeBtnStatus(btn, isSelect) {
          btn.isSelect = isSelect;
          btn.updateSpriteStatus();
        };
        _proto.showWinEnd = function showWinEnd() {};
        _proto.setSelectEnum = function setSelectEnum(_enum) {
          this.gameSelectEnum = Object.values(_enum);
        };
        _proto.getCompo = function getCompo(type) {
          if (!this.mapAllBtn.has(type)) throw new Error("\u7DE8\u8F2F\u5668node\u6A94\u6848\u547D\u540D\u6709\u554F\u984C\uFF0Ctype\u7269\u4EF6\u540D\u7A31\uFF1A" + type + "\uFF0C\u6B63\u78BA\u6027\u8ACB\u4F9D\u7167Select\u5B57\u4E32\u547D\u540D");
          return this.mapAllBtn.get(type);
        };
        _proto.setBtnMap = function setBtnMap(enumType, btn, func) {
          var customEventData = btn.node.name.replace("btn", "");
          if (!Plug.Model.checkHasEnum(enumType, customEventData)) throw new Error("\u7DE8\u8F2F\u5668node\u6A94\u6848\u547D\u540D" + btn.node.name + "\u6709\u554F\u984C\uFF0Ctype\u7269\u4EF6\u540D\u7A31\uFF1A" + customEventData + "\uFF0C\u6B63\u78BA\u6027\u8ACB\u4F9D\u7167Select\u5B57\u4E32\u547D\u540D");
          CustomEvent.addEvent(CEType.ClickEvents, this, Plug.Model.getFunctionName(func), btn, customEventData);
          this.mapAllBtn.set(customEventData, btn);
        };
        return BasicSelect;
      }(BaseComponent), _applyDecoratedDescriptor(_class2.prototype, "onSelect", [setFunctionName], Object.getOwnPropertyDescriptor(_class2.prototype, "onSelect"), _class2.prototype), _class2)) || _class));
      var BasicSendDate = exports('BasicSendDate', function BasicSendDate() {});
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicSFBetInfo.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BasicEnum.ts', './BasicBetInfo.ts', './BasicSPButton.ts'], function (exports) {
  var _applyDecoratedDescriptor, _initializerDefineProperty, _inheritsLoose, _assertThisInitialized, cclegacy, _decorator, SpriteFrame, Platform, BasicBetInfo, BasicSPButton;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _initializerDefineProperty = module.initializerDefineProperty;
      _inheritsLoose = module.inheritsLoose;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      SpriteFrame = module.SpriteFrame;
    }, function (module) {
      Platform = module.Platform;
    }, function (module) {
      BasicBetInfo = module.default;
    }, function (module) {
      BasicSPButton = module.BasicSPButton;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _dec5, _dec6, _dec7, _dec8, _dec9, _dec10, _dec11, _dec12, _dec13, _class, _class2, _descriptor, _descriptor2, _descriptor3, _descriptor4, _descriptor5, _descriptor6, _descriptor7, _descriptor8, _descriptor9, _descriptor10, _descriptor11, _descriptor12, _dec14, _dec15, _class4, _class5, _descriptor13;
      cclegacy._RF.push({}, "1b03fVC9RpOr7Fhfln9CXvl", "BasicSFBetInfo", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var SFBetInfo = (_dec = ccclass("SFBetInfo"), _dec2 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec3 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec4 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec5 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec6 = property({
        group: {
          name: Platform.Mobile
        },
        type: SpriteFrame
      }), _dec7 = property({
        group: {
          name: Platform.Mobile
        },
        type: SpriteFrame
      }), _dec8 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec9 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec10 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec11 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec12 = property({
        group: {
          name: Platform.Web
        },
        type: SpriteFrame
      }), _dec13 = property({
        group: {
          name: Platform.Web
        },
        type: SpriteFrame
      }), _dec(_class = (_class2 = function SFBetInfo() {
        _initializerDefineProperty(this, "mobile_Turbo", _descriptor, this);
        _initializerDefineProperty(this, "mobile_Minus", _descriptor2, this);
        _initializerDefineProperty(this, "mobile_Plus", _descriptor3, this);
        _initializerDefineProperty(this, "mobile_AutoPlay", _descriptor4, this);
        _initializerDefineProperty(this, "mobile_AutoPlayMode", _descriptor5, this);
        _initializerDefineProperty(this, "mobile_TotalBg", _descriptor6, this);
        //<--------------------------------平台分界線-------------------------------------->
        _initializerDefineProperty(this, "web_Turbo", _descriptor7, this);
        _initializerDefineProperty(this, "web_Minus", _descriptor8, this);
        _initializerDefineProperty(this, "web_Plus", _descriptor9, this);
        _initializerDefineProperty(this, "web_AutoPlay", _descriptor10, this);
        _initializerDefineProperty(this, "web_AutoPlayMode", _descriptor11, this);
        _initializerDefineProperty(this, "web_TotalBg", _descriptor12, this);
      }, (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mobile_Turbo", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "mobile_Minus", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "mobile_Plus", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor4 = _applyDecoratedDescriptor(_class2.prototype, "mobile_AutoPlay", [_dec5], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor5 = _applyDecoratedDescriptor(_class2.prototype, "mobile_AutoPlayMode", [_dec6], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SpriteFrame();
        }
      }), _descriptor6 = _applyDecoratedDescriptor(_class2.prototype, "mobile_TotalBg", [_dec7], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SpriteFrame();
        }
      }), _descriptor7 = _applyDecoratedDescriptor(_class2.prototype, "web_Turbo", [_dec8], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor8 = _applyDecoratedDescriptor(_class2.prototype, "web_Minus", [_dec9], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor9 = _applyDecoratedDescriptor(_class2.prototype, "web_Plus", [_dec10], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor10 = _applyDecoratedDescriptor(_class2.prototype, "web_AutoPlay", [_dec11], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor11 = _applyDecoratedDescriptor(_class2.prototype, "web_AutoPlayMode", [_dec12], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SpriteFrame();
        }
      }), _descriptor12 = _applyDecoratedDescriptor(_class2.prototype, "web_TotalBg", [_dec13], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SpriteFrame();
        }
      })), _class2)) || _class);
      var BasicSFBetInfo = exports('default', (_dec14 = ccclass('BasicSFBetInfo'), _dec15 = property(SFBetInfo), _dec14(_class4 = (_class5 = /*#__PURE__*/function (_BasicBetInfo) {
        _inheritsLoose(BasicSFBetInfo, _BasicBetInfo);
        function BasicSFBetInfo() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BasicBetInfo.call.apply(_BasicBetInfo, [this].concat(args)) || this;
          //Bet相關按鈕
          _initializerDefineProperty(_this, "orientationSprite", _descriptor13, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = BasicSFBetInfo.prototype;
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          if (isLandscape) {
            this.btnTurbo.normalSprite = this.orientationSprite.web_Turbo["default"];
            this.btnTurbo.pressedSprite = this.orientationSprite.web_Turbo.press;
            this.btnTurbo.defaultNormalSprite = this.orientationSprite.web_Turbo["default"];
            // this.btnTurbo.defaultDisabledSprite = this.orientationSprite.web_Turbo.disable
            this.btnTurbo.defaultSelectSprite = this.orientationSprite.web_Turbo.press;
            this.btnMinus.normalSprite = this.orientationSprite.web_Minus["default"];
            this.btnMinus.pressedSprite = this.orientationSprite.web_Minus.press;
            this.btnMinus.disabledSprite = this.orientationSprite.web_Minus.disable;
            this.btnPlus.normalSprite = this.orientationSprite.web_Plus["default"];
            this.btnPlus.pressedSprite = this.orientationSprite.web_Plus.press;
            this.btnPlus.disabledSprite = this.orientationSprite.web_Plus.disable;
            this.btnAutoPlay.normalSprite = this.orientationSprite.web_AutoPlay["default"];
            this.btnAutoPlay.pressedSprite = this.orientationSprite.web_AutoPlay.press;
            // this.btnAutoPlay.disabledSprite = this.orientationSprite.web_AutoPlay.press

            this.btnAutoPlayIng.normalSprite = this.orientationSprite.web_AutoPlayMode;
            this.spriteTotalBg.spriteFrame = this.orientationSprite.web_TotalBg;
          } else {
            this.btnTurbo.normalSprite = this.orientationSprite.mobile_Turbo["default"];
            this.btnTurbo.pressedSprite = this.orientationSprite.mobile_Turbo.press;
            this.btnTurbo.defaultNormalSprite = this.orientationSprite.mobile_Turbo["default"];
            // this.btnTurbo.defaultDisabledSprite = this.orientationSprite.mobile_Turbo.disable
            this.btnTurbo.defaultSelectSprite = this.orientationSprite.mobile_Turbo.press;
            this.btnMinus.normalSprite = this.orientationSprite.mobile_Minus["default"];
            this.btnMinus.pressedSprite = this.orientationSprite.mobile_Minus.press;
            this.btnMinus.disabledSprite = this.orientationSprite.mobile_Minus.disable;
            this.btnPlus.normalSprite = this.orientationSprite.mobile_Plus["default"];
            this.btnPlus.pressedSprite = this.orientationSprite.mobile_Plus.press;
            this.btnPlus.disabledSprite = this.orientationSprite.mobile_Plus.disable;
            this.btnAutoPlay.normalSprite = this.orientationSprite.mobile_AutoPlay["default"];
            this.btnAutoPlay.pressedSprite = this.orientationSprite.mobile_AutoPlay.press;
            // this.btnAutoPlay.disabledSprite = this.orientationSprite.mobile_AutoPlay.press

            this.btnAutoPlayIng.normalSprite = this.orientationSprite.mobile_AutoPlayMode;
            this.spriteTotalBg.spriteFrame = this.orientationSprite.mobile_TotalBg;
          }
        };
        return BasicSFBetInfo;
      }(BasicBetInfo), _descriptor13 = _applyDecoratedDescriptor(_class5.prototype, "orientationSprite", [_dec15], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SFBetInfo();
        }
      }), _class5)) || _class4));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicSFPlaySelect.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BasicEnum.ts', './BasicSPButton.ts'], function (exports) {
  var _applyDecoratedDescriptor, _initializerDefineProperty, cclegacy, _decorator, Platform, BasicSPButton;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _initializerDefineProperty = module.initializerDefineProperty;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      Platform = module.Platform;
    }, function (module) {
      BasicSPButton = module.BasicSPButton;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "3b63b7at15OwLzhUbOwU+B1", "BasicSFPlaySelect", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var SFPlaySelect = exports('SFPlaySelect', (_dec = ccclass('BasicSFPlaySelect'), _dec2 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec3 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec(_class = (_class2 = function SFPlaySelect() {
        _initializerDefineProperty(this, "mobile_Play", _descriptor, this);
        //<--------------------------------平台分界線-------------------------------------->
        _initializerDefineProperty(this, "web_Play", _descriptor2, this);
      }, (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mobile_Play", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "web_Play", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicSFRandomSelect.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BasicEnum.ts', './BasicSPButton.ts'], function (exports) {
  var _applyDecoratedDescriptor, _initializerDefineProperty, cclegacy, _decorator, Platform, BasicSPButton;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _initializerDefineProperty = module.initializerDefineProperty;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      Platform = module.Platform;
    }, function (module) {
      BasicSPButton = module.BasicSPButton;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "42065ItKUlPtZ5vkhucknqC", "BasicSFRandomSelect", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var SFRandomSelect = exports('SFRandomSelect', (_dec = ccclass('BasicSPRandonSelect'), _dec2 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec3 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec(_class = (_class2 = function SFRandomSelect() {
        _initializerDefineProperty(this, "mobile_Random", _descriptor, this);
        //<--------------------------------平台分界線-------------------------------------->
        _initializerDefineProperty(this, "web_Random", _descriptor2, this);
      }, (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mobile_Random", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "web_Random", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicSPButton.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _applyDecoratedDescriptor, _initializerDefineProperty, cclegacy, _decorator, SpriteFrame;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _initializerDefineProperty = module.initializerDefineProperty;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      SpriteFrame = module.SpriteFrame;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _class, _class2, _descriptor, _descriptor2, _descriptor3;
      cclegacy._RF.push({}, "cf51ac6QThB3KkNN8GBd4xM", "BasicSPButton", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BasicSPButton = exports('BasicSPButton', (_dec = ccclass("BasicSPButton"), _dec2 = property({
        type: SpriteFrame
      }), _dec3 = property({
        type: SpriteFrame
      }), _dec4 = property({
        type: SpriteFrame
      }), _dec(_class = (_class2 = function BasicSPButton() {
        _initializerDefineProperty(this, "default", _descriptor, this);
        _initializerDefineProperty(this, "press", _descriptor2, this);
        _initializerDefineProperty(this, "disable", _descriptor3, this);
      }, (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "default", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "press", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "disable", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/BasicVersion.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Label, BaseComponent;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Label = module.Label;
    }, function (module) {
      BaseComponent = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "27ac6QISWBG+oFjruRO78Ml", "BasicVersion", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var BasicVersion = exports('default', (_dec = ccclass('BasicVersion'), _dec2 = property(Label), _dec(_class = (_class2 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(BasicVersion, _BaseComponent);
        function BasicVersion() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "labelVersion", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "version", _descriptor2, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = BasicVersion.prototype;
        _proto.onLoad = function onLoad() {
          this.labelVersion.string = this.version + "version";
          _BaseComponent.prototype.onLoad.call(this);
        };
        return BasicVersion;
      }(BaseComponent), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "labelVersion", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "version", [property], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return "";
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/blowfish.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, BlockCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BlockCipher = module.BlockCipher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "bd6feVH3glIJ6+y340WIPEC", "blowfish", undefined);
      var N = 16;

      //Origin pbox and sbox, derived from PI
      var ORIG_P = [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B];
      var ORIG_S = [[0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69, 0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5, 0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E, 0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993, 0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C, 0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239, 0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A, 0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4, 0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706, 0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B, 0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4, 0x5E5C9EC2, 0x196A2463, 0x68FB6FAF, 0x3E6C53B5, 0x1339B2EB, 0x3B52EC6F, 0x6DFC511F, 0x9B30952C, 0xCC814544, 0xAF5EBD09, 0xBEE3D004, 0xDE334AFD, 0x660F2807, 0x192E4BB3, 0xC0CBA857, 0x45C8740F, 0xD20B5F39, 0xB9D3FBDB, 0x5579C0BD, 0x1A60320A, 0xD6A100C6, 0x402C7279, 0x679F25FE, 0xFB1FA3CC, 0x8EA5E9F8, 0xDB3222F8, 0x3C7516DF, 0xFD616B15, 0x2F501EC8, 0xAD0552AB, 0x323DB5FA, 0xFD238760, 0x53317B48, 0x3E00DF82, 0x9E5C57BB, 0xCA6F8CA0, 0x1A87562E, 0xDF1769DB, 0xD542A8F6, 0x287EFFC3, 0xAC6732C6, 0x8C4F5573, 0x695B27B0, 0xBBCA58C8, 0xE1FFA35D, 0xB8F011A0, 0x10FA3D98, 0xFD2183B8, 0x4AFCB56C, 0x2DD1D35B, 0x9A53E479, 0xB6F84565, 0xD28E49BC, 0x4BFB9790, 0xE1DDF2DA, 0xA4CB7E33, 0x62FB1341, 0xCEE4C6E8, 0xEF20CADA, 0x36774C01, 0xD07E9EFE, 0x2BF11FB4, 0x95DBDA4D, 0xAE909198, 0xEAAD8E71, 0x6B93D5A0, 0xD08ED1D0, 0xAFC725E0, 0x8E3C5B2F, 0x8E7594B7, 0x8FF6E2FB, 0xF2122B64, 0x8888B812, 0x900DF01C, 0x4FAD5EA0, 0x688FC31C, 0xD1CFF191, 0xB3A8C1AD, 0x2F2F2218, 0xBE0E1777, 0xEA752DFE, 0x8B021FA1, 0xE5A0CC0F, 0xB56F74E8, 0x18ACF3D6, 0xCE89E299, 0xB4A84FE0, 0xFD13E0B7, 0x7CC43B81, 0xD2ADA8D9, 0x165FA266, 0x80957705, 0x93CC7314, 0x211A1477, 0xE6AD2065, 0x77B5FA86, 0xC75442F5, 0xFB9D35CF, 0xEBCDAF0C, 0x7B3E89A0, 0xD6411BD3, 0xAE1E7E49, 0x00250E2D, 0x2071B35E, 0x226800BB, 0x57B8E0AF, 0x2464369B, 0xF009B91E, 0x5563911D, 0x59DFA6AA, 0x78C14389, 0xD95A537F, 0x207D5BA2, 0x02E5B9C5, 0x83260376, 0x6295CFA9, 0x11C81968, 0x4E734A41, 0xB3472DCA, 0x7B14A94A, 0x1B510052, 0x9A532915, 0xD60F573F, 0xBC9BC6E4, 0x2B60A476, 0x81E67400, 0x08BA6FB5, 0x571BE91F, 0xF296EC6B, 0x2A0DD915, 0xB6636521, 0xE7B9F9B6, 0xFF34052E, 0xC5855664, 0x53B02D5D, 0xA99F8FA1, 0x08BA4799, 0x6E85076A], [0x4B7A70E9, 0xB5B32944, 0xDB75092E, 0xC4192623, 0xAD6EA6B0, 0x49A7DF7D, 0x9CEE60B8, 0x8FEDB266, 0xECAA8C71, 0x699A17FF, 0x5664526C, 0xC2B19EE1, 0x193602A5, 0x75094C29, 0xA0591340, 0xE4183A3E, 0x3F54989A, 0x5B429D65, 0x6B8FE4D6, 0x99F73FD6, 0xA1D29C07, 0xEFE830F5, 0x4D2D38E6, 0xF0255DC1, 0x4CDD2086, 0x8470EB26, 0x6382E9C6, 0x021ECC5E, 0x09686B3F, 0x3EBAEFC9, 0x3C971814, 0x6B6A70A1, 0x687F3584, 0x52A0E286, 0xB79C5305, 0xAA500737, 0x3E07841C, 0x7FDEAE5C, 0x8E7D44EC, 0x5716F2B8, 0xB03ADA37, 0xF0500C0D, 0xF01C1F04, 0x0200B3FF, 0xAE0CF51A, 0x3CB574B2, 0x25837A58, 0xDC0921BD, 0xD19113F9, 0x7CA92FF6, 0x94324773, 0x22F54701, 0x3AE5E581, 0x37C2DADC, 0xC8B57634, 0x9AF3DDA7, 0xA9446146, 0x0FD0030E, 0xECC8C73E, 0xA4751E41, 0xE238CD99, 0x3BEA0E2F, 0x3280BBA1, 0x183EB331, 0x4E548B38, 0x4F6DB908, 0x6F420D03, 0xF60A04BF, 0x2CB81290, 0x24977C79, 0x5679B072, 0xBCAF89AF, 0xDE9A771F, 0xD9930810, 0xB38BAE12, 0xDCCF3F2E, 0x5512721F, 0x2E6B7124, 0x501ADDE6, 0x9F84CD87, 0x7A584718, 0x7408DA17, 0xBC9F9ABC, 0xE94B7D8C, 0xEC7AEC3A, 0xDB851DFA, 0x63094366, 0xC464C3D2, 0xEF1C1847, 0x3215D908, 0xDD433B37, 0x24C2BA16, 0x12A14D43, 0x2A65C451, 0x50940002, 0x133AE4DD, 0x71DFF89E, 0x10314E55, 0x81AC77D6, 0x5F11199B, 0x043556F1, 0xD7A3C76B, 0x3C11183B, 0x5924A509, 0xF28FE6ED, 0x97F1FBFA, 0x9EBABF2C, 0x1E153C6E, 0x86E34570, 0xEAE96FB1, 0x860E5E0A, 0x5A3E2AB3, 0x771FE71C, 0x4E3D06FA, 0x2965DCB9, 0x99E71D0F, 0x803E89D6, 0x5266C825, 0x2E4CC978, 0x9C10B36A, 0xC6150EBA, 0x94E2EA78, 0xA5FC3C53, 0x1E0A2DF4, 0xF2F74EA7, 0x361D2B3D, 0x1939260F, 0x19C27960, 0x5223A708, 0xF71312B6, 0xEBADFE6E, 0xEAC31F66, 0xE3BC4595, 0xA67BC883, 0xB17F37D1, 0x018CFF28, 0xC332DDEF, 0xBE6C5AA5, 0x65582185, 0x68AB9802, 0xEECEA50F, 0xDB2F953B, 0x2AEF7DAD, 0x5B6E2F84, 0x1521B628, 0x29076170, 0xECDD4775, 0x619F1510, 0x13CCA830, 0xEB61BD96, 0x0334FE1E, 0xAA0363CF, 0xB5735C90, 0x4C70A239, 0xD59E9E0B, 0xCBAADE14, 0xEECC86BC, 0x60622CA7, 0x9CAB5CAB, 0xB2F3846E, 0x648B1EAF, 0x19BDF0CA, 0xA02369B9, 0x655ABB50, 0x40685A32, 0x3C2AB4B3, 0x319EE9D5, 0xC021B8F7, 0x9B540B19, 0x875FA099, 0x95F7997E, 0x623D7DA8, 0xF837889A, 0x97E32D77, 0x11ED935F, 0x16681281, 0x0E358829, 0xC7E61FD6, 0x96DEDFA1, 0x7858BA99, 0x57F584A5, 0x1B227263, 0x9B83C3FF, 0x1AC24696, 0xCDB30AEB, 0x532E3054, 0x8FD948E4, 0x6DBC3128, 0x58EBF2EF, 0x34C6FFEA, 0xFE28ED61, 0xEE7C3C73, 0x5D4A14D9, 0xE864B7E3, 0x42105D14, 0x203E13E0, 0x45EEE2B6, 0xA3AAABEA, 0xDB6C4F15, 0xFACB4FD0, 0xC742F442, 0xEF6ABBB5, 0x654F3B1D, 0x41CD2105, 0xD81E799E, 0x86854DC7, 0xE44B476A, 0x3D816250, 0xCF62A1F2, 0x5B8D2646, 0xFC8883A0, 0xC1C7B6A3, 0x7F1524C3, 0x69CB7492, 0x47848A0B, 0x5692B285, 0x095BBF00, 0xAD19489D, 0x1462B174, 0x23820E00, 0x58428D2A, 0x0C55F5EA, 0x1DADF43E, 0x233F7061, 0x3372F092, 0x8D937E41, 0xD65FECF1, 0x6C223BDB, 0x7CDE3759, 0xCBEE7460, 0x4085F2A7, 0xCE77326E, 0xA6078084, 0x19F8509E, 0xE8EFD855, 0x61D99735, 0xA969A7AA, 0xC50C06C2, 0x5A04ABFC, 0x800BCADC, 0x9E447A2E, 0xC3453484, 0xFDD56705, 0x0E1E9EC9, 0xDB73DBD3, 0x105588CD, 0x675FDA79, 0xE3674340, 0xC5C43465, 0x713E38D8, 0x3D28F89E, 0xF16DFF20, 0x153E21E7, 0x8FB03D4A, 0xE6E39F2B, 0xDB83ADF7], [0xE93D5A68, 0x948140F7, 0xF64C261C, 0x94692934, 0x411520F7, 0x7602D4F7, 0xBCF46B2E, 0xD4A20068, 0xD4082471, 0x3320F46A, 0x43B7D4B7, 0x500061AF, 0x1E39F62E, 0x97244546, 0x14214F74, 0xBF8B8840, 0x4D95FC1D, 0x96B591AF, 0x70F4DDD3, 0x66A02F45, 0xBFBC09EC, 0x03BD9785, 0x7FAC6DD0, 0x31CB8504, 0x96EB27B3, 0x55FD3941, 0xDA2547E6, 0xABCA0A9A, 0x28507825, 0x530429F4, 0x0A2C86DA, 0xE9B66DFB, 0x68DC1462, 0xD7486900, 0x680EC0A4, 0x27A18DEE, 0x4F3FFEA2, 0xE887AD8C, 0xB58CE006, 0x7AF4D6B6, 0xAACE1E7C, 0xD3375FEC, 0xCE78A399, 0x406B2A42, 0x20FE9E35, 0xD9F385B9, 0xEE39D7AB, 0x3B124E8B, 0x1DC9FAF7, 0x4B6D1856, 0x26A36631, 0xEAE397B2, 0x3A6EFA74, 0xDD5B4332, 0x6841E7F7, 0xCA7820FB, 0xFB0AF54E, 0xD8FEB397, 0x454056AC, 0xBA489527, 0x55533A3A, 0x20838D87, 0xFE6BA9B7, 0xD096954B, 0x55A867BC, 0xA1159A58, 0xCCA92963, 0x99E1DB33, 0xA62A4A56, 0x3F3125F9, 0x5EF47E1C, 0x9029317C, 0xFDF8E802, 0x04272F70, 0x80BB155C, 0x05282CE3, 0x95C11548, 0xE4C66D22, 0x48C1133F, 0xC70F86DC, 0x07F9C9EE, 0x41041F0F, 0x404779A4, 0x5D886E17, 0x325F51EB, 0xD59BC0D1, 0xF2BCC18F, 0x41113564, 0x257B7834, 0x602A9C60, 0xDFF8E8A3, 0x1F636C1B, 0x0E12B4C2, 0x02E1329E, 0xAF664FD1, 0xCAD18115, 0x6B2395E0, 0x333E92E1, 0x3B240B62, 0xEEBEB922, 0x85B2A20E, 0xE6BA0D99, 0xDE720C8C, 0x2DA2F728, 0xD0127845, 0x95B794FD, 0x647D0862, 0xE7CCF5F0, 0x5449A36F, 0x877D48FA, 0xC39DFD27, 0xF33E8D1E, 0x0A476341, 0x992EFF74, 0x3A6F6EAB, 0xF4F8FD37, 0xA812DC60, 0xA1EBDDF8, 0x991BE14C, 0xDB6E6B0D, 0xC67B5510, 0x6D672C37, 0x2765D43B, 0xDCD0E804, 0xF1290DC7, 0xCC00FFA3, 0xB5390F92, 0x690FED0B, 0x667B9FFB, 0xCEDB7D9C, 0xA091CF0B, 0xD9155EA3, 0xBB132F88, 0x515BAD24, 0x7B9479BF, 0x763BD6EB, 0x37392EB3, 0xCC115979, 0x8026E297, 0xF42E312D, 0x6842ADA7, 0xC66A2B3B, 0x12754CCC, 0x782EF11C, 0x6A124237, 0xB79251E7, 0x06A1BBE6, 0x4BFB6350, 0x1A6B1018, 0x11CAEDFA, 0x3D25BDD8, 0xE2E1C3C9, 0x44421659, 0x0A121386, 0xD90CEC6E, 0xD5ABEA2A, 0x64AF674E, 0xDA86A85F, 0xBEBFE988, 0x64E4C3FE, 0x9DBC8057, 0xF0F7C086, 0x60787BF8, 0x6003604D, 0xD1FD8346, 0xF6381FB0, 0x7745AE04, 0xD736FCCC, 0x83426B33, 0xF01EAB71, 0xB0804187, 0x3C005E5F, 0x77A057BE, 0xBDE8AE24, 0x55464299, 0xBF582E61, 0x4E58F48F, 0xF2DDFDA2, 0xF474EF38, 0x8789BDC2, 0x5366F9C3, 0xC8B38E74, 0xB475F255, 0x46FCD9B9, 0x7AEB2661, 0x8B1DDF84, 0x846A0E79, 0x915F95E2, 0x466E598E, 0x20B45770, 0x8CD55591, 0xC902DE4C, 0xB90BACE1, 0xBB8205D0, 0x11A86248, 0x7574A99E, 0xB77F19B6, 0xE0A9DC09, 0x662D09A1, 0xC4324633, 0xE85A1F02, 0x09F0BE8C, 0x4A99A025, 0x1D6EFE10, 0x1AB93D1D, 0x0BA5A4DF, 0xA186F20F, 0x2868F169, 0xDCB7DA83, 0x573906FE, 0xA1E2CE9B, 0x4FCD7F52, 0x50115E01, 0xA70683FA, 0xA002B5C4, 0x0DE6D027, 0x9AF88C27, 0x773F8641, 0xC3604C06, 0x61A806B5, 0xF0177A28, 0xC0F586E0, 0x006058AA, 0x30DC7D62, 0x11E69ED7, 0x2338EA63, 0x53C2DD94, 0xC2C21634, 0xBBCBEE56, 0x90BCB6DE, 0xEBFC7DA1, 0xCE591D76, 0x6F05E409, 0x4B7C0188, 0x39720A3D, 0x7C927C24, 0x86E3725F, 0x724D9DB9, 0x1AC15BB4, 0xD39EB8FC, 0xED545578, 0x08FCA5B5, 0xD83D7CD3, 0x4DAD0FC4, 0x1E50EF5E, 0xB161E6F8, 0xA28514D9, 0x6C51133C, 0x6FD5C7E7, 0x56E14EC4, 0x362ABFCE, 0xDDC6C837, 0xD79A3234, 0x92638212, 0x670EFA8E, 0x406000E0], [0x3A39CE37, 0xD3FAF5CF, 0xABC27737, 0x5AC52D1B, 0x5CB0679E, 0x4FA33742, 0xD3822740, 0x99BC9BBE, 0xD5118E9D, 0xBF0F7315, 0xD62D1C7E, 0xC700C47B, 0xB78C1B6B, 0x21A19045, 0xB26EB1BE, 0x6A366EB4, 0x5748AB2F, 0xBC946E79, 0xC6A376D2, 0x6549C2C8, 0x530FF8EE, 0x468DDE7D, 0xD5730A1D, 0x4CD04DC6, 0x2939BBDB, 0xA9BA4650, 0xAC9526E8, 0xBE5EE304, 0xA1FAD5F0, 0x6A2D519A, 0x63EF8CE2, 0x9A86EE22, 0xC089C2B8, 0x43242EF6, 0xA51E03AA, 0x9CF2D0A4, 0x83C061BA, 0x9BE96A4D, 0x8FE51550, 0xBA645BD6, 0x2826A2F9, 0xA73A3AE1, 0x4BA99586, 0xEF5562E9, 0xC72FEFD3, 0xF752F7DA, 0x3F046F69, 0x77FA0A59, 0x80E4A915, 0x87B08601, 0x9B09E6AD, 0x3B3EE593, 0xE990FD5A, 0x9E34D797, 0x2CF0B7D9, 0x022B8B51, 0x96D5AC3A, 0x017DA67D, 0xD1CF3ED6, 0x7C7D2D28, 0x1F9F25CF, 0xADF2B89B, 0x5AD6B472, 0x5A88F54C, 0xE029AC71, 0xE019A5E6, 0x47B0ACFD, 0xED93FA9B, 0xE8D3C48D, 0x283B57CC, 0xF8D56629, 0x79132E28, 0x785F0191, 0xED756055, 0xF7960E44, 0xE3D35E8C, 0x15056DD4, 0x88F46DBA, 0x03A16125, 0x0564F0BD, 0xC3EB9E15, 0x3C9057A2, 0x97271AEC, 0xA93A072A, 0x1B3F6D9B, 0x1E6321F5, 0xF59C66FB, 0x26DCF319, 0x7533D928, 0xB155FDF5, 0x03563482, 0x8ABA3CBB, 0x28517711, 0xC20AD9F8, 0xABCC5167, 0xCCAD925F, 0x4DE81751, 0x3830DC8E, 0x379D5862, 0x9320F991, 0xEA7A90C2, 0xFB3E7BCE, 0x5121CE64, 0x774FBE32, 0xA8B6E37E, 0xC3293D46, 0x48DE5369, 0x6413E680, 0xA2AE0810, 0xDD6DB224, 0x69852DFD, 0x09072166, 0xB39A460A, 0x6445C0DD, 0x586CDECF, 0x1C20C8AE, 0x5BBEF7DD, 0x1B588D40, 0xCCD2017F, 0x6BB4E3BB, 0xDDA26A7E, 0x3A59FF45, 0x3E350A44, 0xBCB4CDD5, 0x72EACEA8, 0xFA6484BB, 0x8D6612AE, 0xBF3C6F47, 0xD29BE463, 0x542F5D9E, 0xAEC2771B, 0xF64E6370, 0x740E0D8D, 0xE75B1357, 0xF8721671, 0xAF537D5D, 0x4040CB08, 0x4EB4E2CC, 0x34D2466A, 0x0115AF84, 0xE1B00428, 0x95983A1D, 0x06B89FB4, 0xCE6EA048, 0x6F3F3B82, 0x3520AB82, 0x011A1D4B, 0x277227F8, 0x611560B1, 0xE7933FDC, 0xBB3A792B, 0x344525BD, 0xA08839E1, 0x51CE794B, 0x2F32C9B7, 0xA01FBAC9, 0xE01CC87E, 0xBCC7D1F6, 0xCF0111C3, 0xA1E8AAC7, 0x1A908749, 0xD44FBD9A, 0xD0DADECB, 0xD50ADA38, 0x0339C32A, 0xC6913667, 0x8DF9317C, 0xE0B12B4F, 0xF79E59B7, 0x43F5BB3A, 0xF2D519FF, 0x27D9459C, 0xBF97222C, 0x15E6FC2A, 0x0F91FC71, 0x9B941525, 0xFAE59361, 0xCEB69CEB, 0xC2A86459, 0x12BAA8D1, 0xB6C1075E, 0xE3056A0C, 0x10D25065, 0xCB03A442, 0xE0EC6E0E, 0x1698DB3B, 0x4C98A0BE, 0x3278E964, 0x9F1F9532, 0xE0D392DF, 0xD3A0342B, 0x8971F21E, 0x1B0A7441, 0x4BA3348C, 0xC5BE7120, 0xC37632D8, 0xDF359F8D, 0x9B992F2E, 0xE60B6F47, 0x0FE3F11D, 0xE54CDA54, 0x1EDAD891, 0xCE6279CF, 0xCD3E7E6F, 0x1618B166, 0xFD2C1D05, 0x848FD2C5, 0xF6FB2299, 0xF523F357, 0xA6327623, 0x93A83531, 0x56CCCD02, 0xACF08162, 0x5A75EBB5, 0x6E163697, 0x88D273CC, 0xDE966292, 0x81B949D0, 0x4C50901B, 0x71C65614, 0xE6C6C7BD, 0x327A140A, 0x45E1D006, 0xC3F27B9A, 0xC9AA53FD, 0x62A80F00, 0xBB25BFE2, 0x35BDD2F6, 0x71126905, 0xB2040222, 0xB6CBCF7C, 0xCD769C2B, 0x53113EC0, 0x1640E3D3, 0x38ABBD60, 0x2547ADF0, 0xBA38209C, 0xF746CE76, 0x77AFA1C5, 0x20756060, 0x85CBFE4E, 0x8AE88DD8, 0x7AAAF9B0, 0x4CF9AA7E, 0x1948C25C, 0x02FB8A8C, 0x01C36AE4, 0xD6EBE1F9, 0x90D4F869, 0xA65CDEA0, 0x3F09252D, 0xC208E69F, 0xB74E6132, 0xCE77E25B, 0x578FDFE3, 0x3AC372E6]];
      var blowfishCtx = {
        pbox: [],
        sbox: []
      };
      function f(ctx, x) {
        var a = x >> 24 & 0xFF;
        var b = x >> 16 & 0xFF;
        var c = x >> 8 & 0xFF;
        var d = x & 0xFF;
        var y = ctx.sbox[0][a] + ctx.sbox[1][b];
        y = y ^ ctx.sbox[2][c];
        y = y + ctx.sbox[3][d];
        return y;
      }
      function blowfishEncrypt(ctx, left, right) {
        var Xl = left;
        var Xr = right;
        var temp;
        for (var i = 0; i < N; ++i) {
          Xl = Xl ^ ctx.pbox[i];
          Xr = f(ctx, Xl) ^ Xr;
          temp = Xl;
          Xl = Xr;
          Xr = temp;
        }
        temp = Xl;
        Xl = Xr;
        Xr = temp;
        Xr = Xr ^ ctx.pbox[N];
        Xl = Xl ^ ctx.pbox[N + 1];
        return {
          left: Xl,
          right: Xr
        };
      }
      function blowfishDecrypt(ctx, left, right) {
        var Xl = left;
        var Xr = right;
        var temp;
        for (var i = N + 1; i > 1; --i) {
          Xl = Xl ^ ctx.pbox[i];
          Xr = f(ctx, Xl) ^ Xr;
          temp = Xl;
          Xl = Xr;
          Xr = temp;
        }
        temp = Xl;
        Xl = Xr;
        Xr = temp;
        Xr = Xr ^ ctx.pbox[1];
        Xl = Xl ^ ctx.pbox[0];
        return {
          left: Xl,
          right: Xr
        };
      }

      /**
      * Initialization ctx's pbox and sbox.
      *
      * @param {Object} ctx The object has pbox and sbox.
      * @param {Array} key An array of 32-bit words.
      * @param {int} keysize The length of the key.
      *
      * @example
      *
      *     blowfishInit(BLOWFISH_CTX, key, 128/32);
      */
      function blowfishInit(ctx, key, keysize) {
        for (var Row = 0; Row < 4; Row++) {
          ctx.sbox[Row] = [];
          for (var Col = 0; Col < 256; Col++) {
            ctx.sbox[Row][Col] = ORIG_S[Row][Col];
          }
        }
        var keyIndex = 0;
        for (var index = 0; index < N + 2; index++) {
          ctx.pbox[index] = ORIG_P[index] ^ key[keyIndex];
          keyIndex++;
          if (keyIndex >= keysize) {
            keyIndex = 0;
          }
        }
        var data1 = 0;
        var data2 = 0;
        var res = 0;
        for (var i = 0; i < N + 2; i += 2) {
          res = blowfishEncrypt(ctx, data1, data2);
          data1 = res.left;
          data2 = res.right;
          ctx.pbox[i] = data1;
          ctx.pbox[i + 1] = data2;
        }
        for (var _i = 0; _i < 4; _i++) {
          for (var j = 0; j < 256; j += 2) {
            res = blowfishEncrypt(ctx, data1, data2);
            data1 = res.left;
            data2 = res.right;
            ctx.sbox[_i][j] = data1;
            ctx.sbox[_i][j + 1] = data2;
          }
        }
        return true;
      }

      /**
       * Blowfish block cipher algorithm.
       */
      var BlowfishAlgo = exports('BlowfishAlgo', /*#__PURE__*/function (_BlockCipher) {
        _inheritsLoose(BlowfishAlgo, _BlockCipher);
        function BlowfishAlgo(xformMode, key, cfg) {
          var _this;
          _this = _BlockCipher.call(this, xformMode, key, cfg) || this;

          // blickSize is an instance field and should set in constructor.
          _this.blockSize = 64 / 32;
          return _this;
        }
        var _proto = BlowfishAlgo.prototype;
        _proto._doReset = function _doReset() {
          // Skip reset of nRounds has been set before and key did not change
          if (this._keyPriorReset === this._key) {
            return;
          }

          // Shortcuts
          var key = this._keyPriorReset = this._key;
          var keyWords = key.words;
          var keySize = key.sigBytes / 4;

          //Initialization pbox and sbox
          blowfishInit(blowfishCtx, keyWords, keySize);
        };
        _proto.encryptBlock = function encryptBlock(M, offset) {
          var res = blowfishEncrypt(blowfishCtx, M[offset], M[offset + 1]);
          M[offset] = res.left;
          M[offset + 1] = res.right;
        };
        _proto.decryptBlock = function decryptBlock(M, offset) {
          var res = blowfishDecrypt(blowfishCtx, M[offset], M[offset + 1]);
          M[offset] = res.left;
          M[offset + 1] = res.right;
        };
        return BlowfishAlgo;
      }(BlockCipher));
      BlowfishAlgo.keySize = 128 / 32;
      BlowfishAlgo.ivSize = 64 / 32;
      // blickSize is an instance field and should set in constructor.

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.Blowfish.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.Blowfish.decrypt(ciphertext, key, cfg);
       */
      var Blowfish = exports('Blowfish', BlockCipher._createHelper(BlowfishAlgo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/browser_client.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './base_client.ts'], function (exports) {
  var _inheritsLoose, cclegacy, Client$1;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      Client$1 = module.Client;
    }],
    execute: function () {
      cclegacy._RF.push({}, "3173cenyypGqpswT7LUMC0v", "browser_client", undefined);

      // This client doesn't have any extra options.

      var utf8Encoder = new TextEncoder();
      var utf8Decoder = new TextDecoder();
      var Client = exports('Client', /*#__PURE__*/function (_BaseClient) {
        _inheritsLoose(Client, _BaseClient);
        function Client(options) {
          var _this;
          _this = _BaseClient.call(this, options) || this;
          _this.ws = void 0;
          return _this;
        }
        var _proto = Client.prototype;
        _proto.getUTF8Encoder = function getUTF8Encoder() {
          return utf8Encoder;
        };
        _proto.getUTF8Decoder = function getUTF8Decoder() {
          return utf8Decoder;
        };
        _proto.getDefaultURL = function getDefaultURL() {
          return "ws://localhost";
        };
        _proto.validateURL = function validateURL(url) {
          if (!(url.protocol === "ws:" || url.protocol === "wss:")) {
            throw new Error("URL protocol must be ws or wss");
          }
        };
        _proto.open = function open(url) {
          var _this2 = this;
          var closed = true;
          return new Promise(function (resolve, reject) {
            var ws = new WebSocket(url.toString(), "mqtt");
            ws.binaryType = "arraybuffer";
            _this2.ws = ws;
            ws.onopen = function () {
              _this2.log("connection made");
              closed = false;
              ws.onopen = null;
              ws.onmessage = function (message) {
                var bytes = new Uint8Array(message.data);
                _this2.bytesReceived(bytes);
              };
              ws.onclose = function () {
                if (!closed) {
                  closed = true;
                  _this2.connectionClosed();
                }
              };
              ws.onerror = function (_err) {
                if (!closed) {
                  closed = true;
                  _this2.connectionClosed();
                }
              };
              resolve();
            };
            ws.onerror = function (err) {
              _this2.log("connection error");
              ws.onopen = null;
              ws.onerror = null;
              reject(err);
            };
          });
        };
        _proto.write = function write(bytes) {
          if (!this.ws) {
            return Promise.reject(new Error("no connection"));
          }
          this.log("writing bytes", bytes);
          this.ws.send(bytes);
          return Promise.resolve();
        };
        _proto.close = function close() {
          if (!this.ws) {
            return Promise.reject(new Error("no connection"));
          }
          this.ws.close();
          return Promise.resolve();
        };
        return Client;
      }(Client$1));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/buffer_utils.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports('concat', concat);
      cclegacy._RF.push({}, "b2b11DVJ+lPXpNaKiwmkNBd", "buffer_utils", undefined);
      // import digest from '../runtime/digest'

      var encoder = exports('encoder', new TextEncoder());
      var decoder = exports('decoder', new TextDecoder());

      // const MAX_INT32 = 2 ** 32

      function concat() {
        for (var _len = arguments.length, buffers = new Array(_len), _key = 0; _key < _len; _key++) {
          buffers[_key] = arguments[_key];
        }
        var size = buffers.reduce(function (acc, _ref) {
          var length = _ref.length;
          return acc + length;
        }, 0);
        var buf = new Uint8Array(size);
        var i = 0;
        for (var _i = 0, _buffers = buffers; _i < _buffers.length; _i++) {
          var buffer = _buffers[_i];
          buf.set(buffer, i);
          i += buffer.length;
        }
        return buf;
      }

      // export function p2s(alg: string, p2sInput: Uint8Array) {
      //   return concat(encoder.encode(alg), new Uint8Array([0]), p2sInput)
      // }

      // function writeUInt32BE(buf: Uint8Array, value: number, offset?: number) {
      //   if (value < 0 || value >= MAX_INT32) {
      //     throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`)
      //   }
      //   buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset)
      // }

      // export function uint64be(value: number) {
      //   const high = Math.floor(value / MAX_INT32)
      //   const low = value % MAX_INT32
      //   const buf = new Uint8Array(8)
      //   writeUInt32BE(buf, high, 0)
      //   writeUInt32BE(buf, low, 4)
      //   return buf
      // }

      // export function uint32be(value: number) {
      //   const buf = new Uint8Array(4)
      //   writeUInt32BE(buf, value)
      //   return buf
      // }

      // export function lengthAndInput(input: Uint8Array) {
      //   return concat(uint32be(input.length), input)
      // }

      // export async function concatKdf(secret: Uint8Array, bits: number, value: Uint8Array) {
      //   const iterations = Math.ceil((bits >> 3) / 32)
      //   const res = new Uint8Array(iterations * 32)
      //   for (let iter = 0; iter < iterations; iter++) {
      //     const buf = new Uint8Array(4 + secret.length + value.length)
      //     buf.set(uint32be(iter + 1))
      //     buf.set(secret, 4)
      //     buf.set(value, 4 + secret.length)
      //     res.set(await digest('sha256', buf), iter * 32)
      //   }
      //   return res.slice(0, bits >> 3)
      // }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/check_key_length.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "db350yYfVpA5Zk/0UeA9I6T", "check_key_length", undefined);
      var checkKeyLength = exports('default', function (alg, key) {
        if (alg.startsWith('RS') || alg.startsWith('PS')) {
          var _ref = key.algorithm,
            modulusLength = _ref.modulusLength;
          if (typeof modulusLength !== 'number' || modulusLength < 2048) {
            throw new TypeError(alg + " requires key modulusLength to be 2048 bits or larger");
          }
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/check_key_type.ts", ['cc', './is_key_like.ts', './invalid_key_input.ts'], function (exports) {
  var cclegacy, isKeyLike, types, withAlg;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      isKeyLike = module.default;
      types = module.types;
    }, function (module) {
      withAlg = module.withAlg;
    }],
    execute: function () {
      cclegacy._RF.push({}, "06b574GFydKaoWAqgYRxxs4", "check_key_type", undefined);
      var symmetricTypeCheck = function symmetricTypeCheck(alg, key) {
        if (key instanceof Uint8Array) return;
        if (!isKeyLike(key)) {
          throw new TypeError(withAlg.apply(void 0, [alg, key].concat(types, ['Uint8Array'])));
        }
        if (key.type !== 'secret') {
          throw new TypeError(types.join(' or ') + " instances for symmetric algorithms must be of type \"secret\"");
        }
      };
      var asymmetricTypeCheck = function asymmetricTypeCheck(alg, key, usage) {
        if (!isKeyLike(key)) {
          throw new TypeError(withAlg.apply(void 0, [alg, key].concat(types)));
        }
        if (key.type === 'secret') {
          throw new TypeError(types.join(' or ') + " instances for asymmetric algorithms must not be of type \"secret\"");
        }
        if (usage === 'sign' && key.type === 'public') {
          throw new TypeError(types.join(' or ') + " instances for asymmetric algorithm signing must be of type \"private\"");
        }
        if (usage === 'decrypt' && key.type === 'public') {
          throw new TypeError(types.join(' or ') + " instances for asymmetric algorithm decryption must be of type \"private\"");
        }

        // KeyObject allows this but CryptoKey does not.
        if (key.algorithm && usage === 'verify' && key.type === 'private') {
          throw new TypeError(types.join(' or ') + " instances for asymmetric algorithm verifying must be of type \"public\"");
        }

        // KeyObject allows this but CryptoKey does not.
        if (key.algorithm && usage === 'encrypt' && key.type === 'private') {
          throw new TypeError(types.join(' or ') + " instances for asymmetric algorithm encryption must be of type \"public\"");
        }
      };
      var checkKeyType = exports('default', function checkKeyType(alg, key, usage) {
        var symmetric = alg.startsWith('HS') || alg === 'dir' || alg.startsWith('PBES2') || /^A\d{3}(?:GCM)?KW$/.test(alg);
        if (symmetric) {
          symmetricTypeCheck(alg, key);
        } else {
          asymmetricTypeCheck(alg, key, usage);
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/cipher-core.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js', './enc-base64.js', './evpkdf.js'], function (exports) {
  var _inheritsLoose, cclegacy, BufferedBlockAlgorithm, WordArray, Base, Base64, EvpKDFAlgo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BufferedBlockAlgorithm = module.BufferedBlockAlgorithm;
      WordArray = module.WordArray;
      Base = module.Base;
    }, function (module) {
      Base64 = module.Base64;
    }, function (module) {
      EvpKDFAlgo = module.EvpKDFAlgo;
    }],
    execute: function () {
      cclegacy._RF.push({}, "2d972yir0pDlJBxsMfPIXHU", "cipher-core", undefined);

      /**
       * Abstract base cipher template.
       *
       * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
       * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
       * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
       * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
       */
      var Cipher = exports('Cipher', /*#__PURE__*/function (_BufferedBlockAlgorit) {
        _inheritsLoose(Cipher, _BufferedBlockAlgorit);
        /**
         * Initializes a newly created cipher.
         *
         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.create(
         *       CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray }
         *     );
         */
        function Cipher(xformMode, key, cfg) {
          var _this;
          _this = _BufferedBlockAlgorit.call(this) || this;

          /**
           * Configuration options.
           *
           * @property {WordArray} iv The IV to use for this operation.
           */
          _this.cfg = Object.assign(new Base(), cfg);

          // Store transform mode and key
          _this._xformMode = xformMode;
          _this._key = key;

          // Set initial values
          _this.reset();
          return _this;
        }

        /**
         * Creates this cipher in encryption mode.
         *
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {Cipher} A cipher instance.
         *
         * @static
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
         */
        Cipher.createEncryptor = function createEncryptor(key, cfg) {
          return this.create(this._ENC_XFORM_MODE, key, cfg);
        }

        /**
         * Creates this cipher in decryption mode.
         *
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {Cipher} A cipher instance.
         *
         * @static
         *
         * @example
         *
         *     const cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
         */;
        Cipher.createDecryptor = function createDecryptor(key, cfg) {
          return this.create(this._DEC_XFORM_MODE, key, cfg);
        }

        /**
         * Creates shortcut functions to a cipher's object interface.
         *
         * @param {Cipher} cipher The cipher to create a helper for.
         *
         * @return {Object} An object with encrypt and decrypt shortcut functions.
         *
         * @static
         *
         * @example
         *
         *     const AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
         */;
        Cipher._createHelper = function _createHelper(SubCipher) {
          var selectCipherStrategy = function selectCipherStrategy(key) {
            if (typeof key === 'string') {
              return PasswordBasedCipher;
            }
            return SerializableCipher;
          };
          return {
            encrypt: function encrypt(message, key, cfg) {
              return selectCipherStrategy(key).encrypt(SubCipher, message, key, cfg);
            },
            decrypt: function decrypt(ciphertext, key, cfg) {
              return selectCipherStrategy(key).decrypt(SubCipher, ciphertext, key, cfg);
            }
          };
        }

        /**
         * Resets this cipher to its initial state.
         *
         * @example
         *
         *     cipher.reset();
         */;
        var _proto = Cipher.prototype;
        _proto.reset = function reset() {
          // Reset data buffer
          _BufferedBlockAlgorit.prototype.reset.call(this);

          // Perform concrete-cipher logic
          this._doReset();
        }

        /**
         * Adds data to be encrypted or decrypted.
         *
         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
         *
         * @return {WordArray} The data after processing.
         *
         * @example
         *
         *     const encrypted = cipher.process('data');
         *     const encrypted = cipher.process(wordArray);
         */;
        _proto.process = function process(dataUpdate) {
          // Append
          this._append(dataUpdate);

          // Process available blocks
          return this._process();
        }

        /**
         * Finalizes the encryption or decryption process.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
         *
         * @return {WordArray} The data after final processing.
         *
         * @example
         *
         *     const encrypted = cipher.finalize();
         *     const encrypted = cipher.finalize('data');
         *     const encrypted = cipher.finalize(wordArray);
         */;
        _proto.finalize = function finalize(dataUpdate) {
          // Final data update
          if (dataUpdate) {
            this._append(dataUpdate);
          }

          // Perform concrete-cipher logic
          var finalProcessedData = this._doFinalize();
          return finalProcessedData;
        };
        return Cipher;
      }(BufferedBlockAlgorithm));
      Cipher._ENC_XFORM_MODE = 1;
      Cipher._DEC_XFORM_MODE = 2;
      Cipher.keySize = 128 / 32;
      Cipher.ivSize = 128 / 32;

      /**
       * Abstract base stream cipher template.
       *
       * @property {number} blockSize
       *
       *     The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
       */
      var StreamCipher = exports('StreamCipher', /*#__PURE__*/function (_Cipher) {
        _inheritsLoose(StreamCipher, _Cipher);
        function StreamCipher() {
          var _this2;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this2 = _Cipher.call.apply(_Cipher, [this].concat(args)) || this;
          _this2.blockSize = 1;
          return _this2;
        }
        var _proto2 = StreamCipher.prototype;
        _proto2._doFinalize = function _doFinalize() {
          // Process partial blocks
          var finalProcessedBlocks = this._process(!!'flush');
          return finalProcessedBlocks;
        };
        return StreamCipher;
      }(Cipher));

      /**
       * Abstract base block cipher mode template.
       */
      var BlockCipherMode = exports('BlockCipherMode', /*#__PURE__*/function (_Base) {
        _inheritsLoose(BlockCipherMode, _Base);
        /**
         * Initializes a newly created mode.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
         */
        function BlockCipherMode(cipher, iv) {
          var _this3;
          _this3 = _Base.call(this) || this;
          _this3._cipher = cipher;
          _this3._iv = iv;
          return _this3;
        }

        /**
         * Creates this mode for encryption.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @static
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
         */
        BlockCipherMode.createEncryptor = function createEncryptor(cipher, iv) {
          return this.Encryptor.create(cipher, iv);
        }

        /**
         * Creates this mode for decryption.
         *
         * @param {Cipher} cipher A block cipher instance.
         * @param {Array} iv The IV words.
         *
         * @static
         *
         * @example
         *
         *     const mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
         */;
        BlockCipherMode.createDecryptor = function createDecryptor(cipher, iv) {
          return this.Decryptor.create(cipher, iv);
        };
        return BlockCipherMode;
      }(Base));
      function xorBlock(words, offset, blockSize) {
        var _words = words;
        var block;

        // Shortcut
        var iv = this._iv;

        // Choose mixing block
        if (iv) {
          block = iv;

          // Remove IV for subsequent blocks
          this._iv = undefined;
        } else {
          block = this._prevBlock;
        }

        // XOR blocks
        for (var i = 0; i < blockSize; i += 1) {
          _words[offset + i] ^= block[i];
        }
      }

      /**
       * Cipher Block Chaining mode.
       */

      /**
       * Abstract base CBC mode.
       */
      var CBC = exports('CBC', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CBC, _BlockCipherMode);
        function CBC() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CBC;
      }(BlockCipherMode));
      /**
       * CBC encryptor.
       */
      CBC.Encryptor = /*#__PURE__*/function (_CBC) {
        _inheritsLoose(_class, _CBC);
        function _class() {
          return _CBC.apply(this, arguments) || this;
        }
        var _proto3 = _class.prototype;
        /**
         * Processes the data block at offset.
         *
         * @param {Array} words The data words to operate on.
         * @param {number} offset The offset where the block starts.
         *
         * @example
         *
         *     mode.processBlock(data.words, offset);
         */
        _proto3.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;

          // XOR and encrypt
          xorBlock.call(this, words, offset, blockSize);
          cipher.encryptBlock(words, offset);

          // Remember this block to use with next block
          this._prevBlock = words.slice(offset, offset + blockSize);
        };
        return _class;
      }(CBC);
      /**
       * CBC decryptor.
       */
      CBC.Decryptor = /*#__PURE__*/function (_CBC2) {
        _inheritsLoose(_class2, _CBC2);
        function _class2() {
          return _CBC2.apply(this, arguments) || this;
        }
        var _proto4 = _class2.prototype;
        /**
         * Processes the data block at offset.
         *
         * @param {Array} words The data words to operate on.
         * @param {number} offset The offset where the block starts.
         *
         * @example
         *
         *     mode.processBlock(data.words, offset);
         */
        _proto4.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;

          // Remember this block to use with next block
          var thisBlock = words.slice(offset, offset + blockSize);

          // Decrypt and XOR
          cipher.decryptBlock(words, offset);
          xorBlock.call(this, words, offset, blockSize);

          // This block becomes the previous block
          this._prevBlock = thisBlock;
        };
        return _class2;
      }(CBC);

      /**
       * PKCS #5/7 padding strategy.
       */
      var Pkcs7 = exports('Pkcs7', {
        /**
         * Pads data using the algorithm defined in PKCS #5/7.
         *
         * @param {WordArray} data The data to pad.
         * @param {number} blockSize The multiple that the data should be padded to.
         *
         * @static
         *
         * @example
         *
         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
         */
        pad: function pad(data, blockSize) {
          // Shortcut
          var blockSizeBytes = blockSize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

          // Create padding word
          var paddingWord = nPaddingBytes << 24 | nPaddingBytes << 16 | nPaddingBytes << 8 | nPaddingBytes;

          // Create padding
          var paddingWords = [];
          for (var i = 0; i < nPaddingBytes; i += 4) {
            paddingWords.push(paddingWord);
          }
          var padding = WordArray.create(paddingWords, nPaddingBytes);

          // Add padding
          data.concat(padding);
        },
        /**
         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
         *
         * @param {WordArray} data The data to unpad.
         *
         * @static
         *
         * @example
         *
         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
         */
        unpad: function unpad(data) {
          var _data = data;

          // Get number of padding bytes from last byte
          var nPaddingBytes = _data.words[_data.sigBytes - 1 >>> 2] & 0xff;

          // Remove padding
          _data.sigBytes -= nPaddingBytes;
        }
      });

      /**
       * Abstract base block cipher template.
       *
       * @property {number} blockSize
       *
       *    The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
       */
      var BlockCipher = exports('BlockCipher', /*#__PURE__*/function (_Cipher2) {
        _inheritsLoose(BlockCipher, _Cipher2);
        function BlockCipher(xformMode, key, cfg) {
          var _this4;
          /**
           * Configuration options.
           *
           * @property {Mode} mode The block mode to use. Default: CBC
           * @property {Padding} padding The padding strategy to use. Default: Pkcs7
           */
          _this4 = _Cipher2.call(this, xformMode, key, Object.assign({
            mode: CBC,
            padding: Pkcs7
          }, cfg)) || this;
          _this4.blockSize = 128 / 32;
          return _this4;
        }
        var _proto5 = BlockCipher.prototype;
        _proto5.reset = function reset() {
          var modeCreator;

          // Reset cipher
          _Cipher2.prototype.reset.call(this);

          // Shortcuts
          var cfg = this.cfg;
          var iv = cfg.iv,
            mode = cfg.mode;

          // Reset block mode
          if (this._xformMode === this.constructor._ENC_XFORM_MODE) {
            modeCreator = mode.createEncryptor;
          } else /* if (this._xformMode == this._DEC_XFORM_MODE) */{
              modeCreator = mode.createDecryptor;
              // Keep at least one block in the buffer for unpadding
              this._minBufferSize = 1;
            }
          this._mode = modeCreator.call(mode, this, iv && iv.words);
          this._mode.__creator = modeCreator;
        };
        _proto5._doProcessBlock = function _doProcessBlock(words, offset) {
          this._mode.processBlock(words, offset);
        };
        _proto5._doFinalize = function _doFinalize() {
          var finalProcessedBlocks;

          // Shortcut
          var padding = this.cfg.padding;

          // Finalize
          if (this._xformMode === this.constructor._ENC_XFORM_MODE) {
            // Pad data
            padding.pad(this._data, this.blockSize);

            // Process final blocks
            finalProcessedBlocks = this._process(!!'flush');
          } else /* if (this._xformMode == this._DEC_XFORM_MODE) */{
              // Process final blocks
              finalProcessedBlocks = this._process(!!'flush');

              // Unpad data
              padding.unpad(finalProcessedBlocks);
            }
          return finalProcessedBlocks;
        };
        return BlockCipher;
      }(Cipher));

      /**
       * A collection of cipher parameters.
       *
       * @property {WordArray} ciphertext The raw ciphertext.
       * @property {WordArray} key The key to this ciphertext.
       * @property {WordArray} iv The IV used in the ciphering operation.
       * @property {WordArray} salt The salt used with a key derivation function.
       * @property {Cipher} algorithm The cipher algorithm.
       * @property {Mode} mode The block mode used in the ciphering operation.
       * @property {Padding} padding The padding scheme used in the ciphering operation.
       * @property {number} blockSize The block size of the cipher.
       * @property {Format} formatter
       *    The default formatting strategy to convert this cipher params object to a string.
       */
      var CipherParams = exports('CipherParams', /*#__PURE__*/function (_Base2) {
        _inheritsLoose(CipherParams, _Base2);
        /**
         * Initializes a newly created cipher params object.
         *
         * @param {Object} cipherParams An object with any of the possible cipher parameters.
         *
         * @example
         *
         *     var cipherParams = CryptoJS.lib.CipherParams.create({
         *         ciphertext: ciphertextWordArray,
         *         key: keyWordArray,
         *         iv: ivWordArray,
         *         salt: saltWordArray,
         *         algorithm: CryptoJS.algo.AES,
         *         mode: CryptoJS.mode.CBC,
         *         padding: CryptoJS.pad.PKCS7,
         *         blockSize: 4,
         *         formatter: CryptoJS.format.OpenSSL
         *     });
         */
        function CipherParams(cipherParams) {
          var _this5;
          _this5 = _Base2.call(this) || this;
          _this5.mixIn(cipherParams);
          return _this5;
        }

        /**
         * Converts this cipher params object to a string.
         *
         * @param {Format} formatter (Optional) The formatting strategy to use.
         *
         * @return {string} The stringified cipher params.
         *
         * @throws Error If neither the formatter nor the default formatter is set.
         *
         * @example
         *
         *     var string = cipherParams + '';
         *     var string = cipherParams.toString();
         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
         */
        var _proto6 = CipherParams.prototype;
        _proto6.toString = function toString(formatter) {
          return (formatter || this.formatter).stringify(this);
        };
        return CipherParams;
      }(Base));

      /**
       * OpenSSL formatting strategy.
       */
      var OpenSSLFormatter = exports('OpenSSLFormatter', {
        /**
         * Converts a cipher params object to an OpenSSL-compatible string.
         *
         * @param {CipherParams} cipherParams The cipher params object.
         *
         * @return {string} The OpenSSL-compatible string.
         *
         * @static
         *
         * @example
         *
         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
         */
        stringify: function stringify(cipherParams) {
          var wordArray;

          // Shortcuts
          var ciphertext = cipherParams.ciphertext,
            salt = cipherParams.salt;

          // Format
          if (salt) {
            wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
          } else {
            wordArray = ciphertext;
          }
          return wordArray.toString(Base64);
        },
        /**
         * Converts an OpenSSL-compatible string to a cipher params object.
         *
         * @param {string} openSSLStr The OpenSSL-compatible string.
         *
         * @return {CipherParams} The cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
         */
        parse: function parse(openSSLStr) {
          var salt;

          // Parse base64
          var ciphertext = Base64.parse(openSSLStr);

          // Shortcut
          var ciphertextWords = ciphertext.words;

          // Test for salt
          if (ciphertextWords[0] === 0x53616c74 && ciphertextWords[1] === 0x65645f5f) {
            // Extract salt
            salt = WordArray.create(ciphertextWords.slice(2, 4));

            // Remove salt from ciphertext
            ciphertextWords.splice(0, 4);
            ciphertext.sigBytes -= 16;
          }
          return CipherParams.create({
            ciphertext: ciphertext,
            salt: salt
          });
        }
      });

      /**
       * A cipher wrapper that returns ciphertext as a serializable cipher params object.
       */
      var SerializableCipher = exports('SerializableCipher', /*#__PURE__*/function (_Base3) {
        _inheritsLoose(SerializableCipher, _Base3);
        function SerializableCipher() {
          return _Base3.apply(this, arguments) || this;
        }
        /**
         * Encrypts a message.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {WordArray|string} message The message to encrypt.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {CipherParams} A cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key);
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       .encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
         */
        SerializableCipher.encrypt = function encrypt(cipher, message, key, cfg) {
          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Encrypt
          var encryptor = cipher.createEncryptor(key, _cfg);
          var ciphertext = encryptor.finalize(message);

          // Shortcut
          var cipherCfg = encryptor.cfg;

          // Create and return serializable cipher params
          return CipherParams.create({
            ciphertext: ciphertext,
            key: key,
            iv: cipherCfg.iv,
            algorithm: cipher,
            mode: cipherCfg.mode,
            padding: cipherCfg.padding,
            blockSize: encryptor.blockSize,
            formatter: _cfg.format
          });
        }

        /**
         * Decrypts serialized ciphertext.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
         * @param {WordArray} key The key.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {WordArray} The plaintext.
         *
         * @static
         *
         * @example
         *
         *     var plaintext = CryptoJS.lib.SerializableCipher
         *       .decrypt(CryptoJS.algo.AES, formattedCiphertext, key,
         *         { iv: iv, format: CryptoJS.format.OpenSSL });
         *     var plaintext = CryptoJS.lib.SerializableCipher
         *       .decrypt(CryptoJS.algo.AES, ciphertextParams, key,
         *         { iv: iv, format: CryptoJS.format.OpenSSL });
         */;
        SerializableCipher.decrypt = function decrypt(cipher, ciphertext, key, cfg) {
          var _ciphertext = ciphertext;

          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Convert string to CipherParams
          _ciphertext = this._parse(_ciphertext, _cfg.format);

          // Decrypt
          var plaintext = cipher.createDecryptor(key, _cfg).finalize(_ciphertext.ciphertext);
          return plaintext;
        }

        /**
         * Converts serialized ciphertext to CipherParams,
         * else assumed CipherParams already and returns ciphertext unchanged.
         *
         * @param {CipherParams|string} ciphertext The ciphertext.
         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
         *
         * @return {CipherParams} The unserialized ciphertext.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.SerializableCipher
         *       ._parse(ciphertextStringOrParams, format);
         */;
        SerializableCipher._parse = function _parse(ciphertext, format) {
          if (typeof ciphertext === 'string') {
            return format.parse(ciphertext, this);
          }
          return ciphertext;
        };
        return SerializableCipher;
      }(Base));
      /**
       * Configuration options.
       *
       * @property {Formatter} format
       *
       *    The formatting strategy to convert cipher param objects to and from a string.
       *    Default: OpenSSL
       */
      SerializableCipher.cfg = Object.assign(new Base(), {
        format: OpenSSLFormatter
      });

      /**
       * OpenSSL key derivation function.
       */
      var OpenSSLKdf = exports('OpenSSLKdf', {
        /**
         * Derives a key and IV from a password.
         *
         * @param {string} password The password to derive from.
         * @param {number} keySize The size in words of the key to generate.
         * @param {number} ivSize The size in words of the IV to generate.
         * @param {WordArray|string} salt
         *     (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
         *
         * @return {CipherParams} A cipher params object with the key, IV, and salt.
         *
         * @static
         *
         * @example
         *
         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
         */
        execute: function execute(password, keySize, ivSize, salt, hasher) {
          var _salt = salt;

          // Generate random salt
          if (!_salt) {
            _salt = WordArray.random(64 / 8);
          }

          // Derive key and IV
          var key;
          if (!hasher) {
            key = EvpKDFAlgo.create({
              keySize: keySize + ivSize
            }).compute(password, _salt);
          } else {
            key = EvpKDFAlgo.create({
              keySize: keySize + ivSize,
              hasher: hasher
            }).compute(password, _salt);
          }

          // Separate key and IV
          var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
          key.sigBytes = keySize * 4;

          // Return params
          return CipherParams.create({
            key: key,
            iv: iv,
            salt: _salt
          });
        }
      });

      /**
       * A serializable cipher wrapper that derives the key from a password,
       * and returns ciphertext as a serializable cipher params object.
       */
      var PasswordBasedCipher = exports('PasswordBasedCipher', /*#__PURE__*/function (_SerializableCipher) {
        _inheritsLoose(PasswordBasedCipher, _SerializableCipher);
        function PasswordBasedCipher() {
          return _SerializableCipher.apply(this, arguments) || this;
        }
        /**
         * Encrypts a message using a password.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {WordArray|string} message The message to encrypt.
         * @param {string} password The password.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {CipherParams} A cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher
         *       .encrypt(CryptoJS.algo.AES, message, 'password');
         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher
         *       .encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
         */
        PasswordBasedCipher.encrypt = function encrypt(cipher, message, password, cfg) {
          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Derive key and other params
          var derivedParams = _cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, _cfg.salt, _cfg.hasher);

          // Add IV to config
          _cfg.iv = derivedParams.iv;

          // Encrypt
          var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, _cfg);

          // Mix in derived params
          ciphertext.mixIn(derivedParams);
          return ciphertext;
        }

        /**
         * Decrypts serialized ciphertext using a password.
         *
         * @param {Cipher} cipher The cipher algorithm to use.
         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
         * @param {string} password The password.
         * @param {Object} cfg (Optional) The configuration options to use for this operation.
         *
         * @return {WordArray} The plaintext.
         *
         * @static
         *
         * @example
         *
         *     var plaintext = CryptoJS.lib.PasswordBasedCipher
         *       .decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password',
         *         { format: CryptoJS.format.OpenSSL });
         *     var plaintext = CryptoJS.lib.PasswordBasedCipher
         *       .decrypt(CryptoJS.algo.AES, ciphertextParams, 'password',
         *         { format: CryptoJS.format.OpenSSL });
         */;
        PasswordBasedCipher.decrypt = function decrypt(cipher, ciphertext, password, cfg) {
          var _ciphertext = ciphertext;

          // Apply config defaults
          var _cfg = Object.assign(new Base(), this.cfg, cfg);

          // Convert string to CipherParams
          _ciphertext = this._parse(_ciphertext, _cfg.format);

          // Derive key and other params
          var derivedParams = _cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, _ciphertext.salt, _cfg.hasher);

          // Add IV to config
          _cfg.iv = derivedParams.iv;

          // Decrypt
          var plaintext = SerializableCipher.decrypt.call(this, cipher, _ciphertext, derivedParams.key, _cfg);
          return plaintext;
        };
        return PasswordBasedCipher;
      }(SerializableCipher));
      /**
       * Configuration options.
       *
       * @property {KDF} kdf
       *     The key derivation function to use to generate a key and IV from a password.
       *     Default: OpenSSL
       */
      PasswordBasedCipher.cfg = Object.assign(SerializableCipher.cfg, {
        kdf: OpenSSLKdf
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/CocosImage.ts", ['cc'], function (exports) {
  var cclegacy, SpriteAtlas, Texture2D, SpriteFrame, path, ImageAsset, Rect, Size, Vec2;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
      SpriteAtlas = module.SpriteAtlas;
      Texture2D = module.Texture2D;
      SpriteFrame = module.SpriteFrame;
      path = module.path;
      ImageAsset = module.ImageAsset;
      Rect = module.Rect;
      Size = module.Size;
      Vec2 = module.Vec2;
    }],
    execute: function () {
      cclegacy._RF.push({}, "8b32brj4I9M3qpJbBtql0dh", "CocosImage", undefined);
      var CocosImage = exports('default', /*#__PURE__*/function () {
        function CocosImage() {}
        CocosImage.tfTextureToSpriteAtlas = function tfTextureToSpriteAtlas(plist, imageAsset) {
          var info = plist["_nativeAsset"]["metadata"];
          var frames = plist["_nativeAsset"]["frames"];
          var atlas = new SpriteAtlas();
          // console.log(atlas);

          var spriteFrames = atlas["spriteFrames"];

          // cc.log(plist);

          for (var key in frames) {
            var texture = new Texture2D();
            texture.image = imageAsset;
            var frame = frames[key];
            var rotated = false,
              sourceSize = void 0,
              offsetStr = void 0,
              textureRect = void 0;
            if (info.format === 0) {
              rotated = false;
              sourceSize = "{" + frame.originalWidth + "," + frame.originalHeight + "}";
              offsetStr = "{" + frame.offsetX + "," + frame.offsetY + "}";
              textureRect = "{{" + frame.x + "," + frame.y + "},{" + frame.width + "," + frame.height + "}}";
            } else if (info.format === 1 || info.format === 2) {
              rotated = frame.rotated;
              sourceSize = frame.sourceSize;
              offsetStr = frame.offset;
              textureRect = frame.frame;
            } else if (info.format === 3) {
              rotated = frame.textureRotated;
              sourceSize = frame.spriteSourceSize;
              offsetStr = frame.spriteOffset;
              textureRect = frame.textureRect;
            }
            var sprite = new SpriteFrame();
            // console.log(sprite);

            sprite.reset({
              originalSize: this.parseSize(sourceSize),
              rect: this.parseRect(textureRect),
              offset: this.parseVec2(offsetStr),
              isRotate: !!rotated,
              texture: texture
            });
            if (frame.triangles) {
              var vertices = this.parseVertices(frame.vertices);
              var verticesUV = this.parseVertices(frame.verticesUV);
              //@ts-ignore
              sprite["vertices"] = {
                triangles: this.parseTriangles(frame.triangles),
                x: [],
                y: [],
                u: [],
                v: []
              };
              for (var i = 0; i < vertices.length; i += 2) {
                sprite["vertices"].x.push(vertices[i]);
                sprite["vertices"].y.push(vertices[i + 1]);
              }
              for (var _i = 0; _i < verticesUV.length; _i += 2) {
                sprite["vertices"].u.push(verticesUV[_i]);
                sprite["vertices"].v.push(verticesUV[_i + 1]);
              }
            }
            var name = path.mainFileName(key);
            sprite.name = name;
            spriteFrames[name] = sprite;
          }
          return atlas;
        };
        CocosImage.tfImageToBase64 = function tfImageToBase64(asset, cb) {
          var canvas = document.createElement("canvas");
          var ctx = canvas.getContext("2d");
          var img = asset.data;
          canvas.width = asset.width;
          canvas.height = asset.height;
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          var dataURL = canvas.toDataURL('image/png');
          cb(dataURL);
        };
        CocosImage.tfBase64ToImage = function tfBase64ToImage(str, cb) {
          var image = new Image();
          image.onload = function () {
            var img = new ImageAsset(image);
            var texture = new Texture2D();
            texture.image = img;
            var sp = new SpriteFrame();
            sp.texture = texture;
            cb(sp);
          };
          image.src = str;
        };
        CocosImage.parseRect = function parseRect(rectStr) {
          rectStr = rectStr.replace(this.BRACE_REGEX, '');
          var arr = rectStr.split(',');
          return new Rect(parseFloat(arr[0] || 0), parseFloat(arr[1] || 0), parseFloat(arr[2] || 0), parseFloat(arr[3] || 0));
        };
        CocosImage.parseSize = function parseSize(sizeStr) {
          sizeStr = sizeStr.slice(1, -1);
          var arr = sizeStr.split(',');
          var width = parseFloat(arr[0]);
          var height = parseFloat(arr[1]);
          return new Size(width, height);
        };
        CocosImage.parseVec2 = function parseVec2(vec2Str) {
          vec2Str = vec2Str.slice(1, -1);
          var arr = vec2Str.split(',');
          var x = parseFloat(arr[0]);
          var y = parseFloat(arr[1]);
          return new Vec2(x, y);
        };
        CocosImage.parseTriangles = function parseTriangles(trianglesStr) {
          return trianglesStr.split(' ').map(parseFloat);
        };
        CocosImage.parseVertices = function parseVertices(verticesStr) {
          return verticesStr.split(' ').map(parseFloat);
        };
        return CocosImage;
      }());
      CocosImage.BRACE_REGEX = /[\{\}]/g;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/CommonValue.ts", ['cc', './BasicEnum.ts'], function (exports) {
  var cclegacy, Platform;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      Platform = module.Platform;
    }],
    execute: function () {
      cclegacy._RF.push({}, "a9accOneOtI/oAMZAi7EB0c", "CommonValue", undefined);
      var CommonValue = exports('default', function CommonValue() {});
      CommonValue.turboLevel = 0;
      CommonValue.isTurbo = false;
      CommonValue.isAuto = false;
      CommonValue.platform = Platform.Web;
      CommonValue.endShow = false;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/connack.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "d9361i7Pr9EY4z//tfFdrxE", "connack", undefined);
      function encode(packet) {
        var packetType = 2;
        var flags = 0;
        return Uint8Array.from([(packetType << 4) + flags, 2, packet.sessionPresent ? 1 : 0, packet.returnCode || 0]);
      }
      function decode(buffer, _remainingStart, remainingLength) {
        if (remainingLength !== 2) {
          throw new Error("connack packets must have a length of 2");
        }
        var sessionPresent = !!(buffer[2] & 1);
        var returnCode = buffer[3];
        return {
          type: "connack",
          sessionPresent: sessionPresent,
          returnCode: returnCode
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/connect.ts", ['cc', './length.ts', './utf8.ts'], function (exports) {
  var cclegacy, encodeLength, encodeUTF8String, decodeUTF8String;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      encodeLength = module.encodeLength;
    }, function (module) {
      encodeUTF8String = module.encodeUTF8String;
      decodeUTF8String = module.decodeUTF8String;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "622cc2QiMdABY9df+nbJjB0", "connect", undefined);
      function encode(packet, utf8Encoder) {
        var packetType = 1;
        var flags = 0;
        var protocolName = encodeUTF8String("MQTT", utf8Encoder);
        var protocolLevel = 4;
        var usernameFlag = !!packet.username;
        var passwordFlag = !!packet.password;
        var willRetain = !!(packet.will && packet.will.retain);
        var willQoS = packet.will && packet.will.qos || 0;
        var willFlag = !!packet.will;
        var cleanSession = packet.clean || typeof packet.clean === "undefined";
        var connectFlags = (usernameFlag ? 128 : 0) + (passwordFlag ? 64 : 0) + (willRetain ? 32 : 0) + (willQoS & 2 ? 16 : 0) + (willQoS & 1 ? 8 : 0) + (willFlag ? 4 : 0) + (cleanSession ? 2 : 0);
        var keepAlive = packet.keepAlive && typeof packet.keepAlive !== "undefined" ? packet.keepAlive : 0;
        var variableHeader = [].concat(protocolName, [protocolLevel, connectFlags, keepAlive >> 8, keepAlive & 0xff]);
        var payload = [].concat(encodeUTF8String(packet.clientId, utf8Encoder));
        if (packet.username) {
          payload.push.apply(payload, encodeUTF8String(packet.username, utf8Encoder));
        }
        if (packet.password) {
          payload.push.apply(payload, encodeUTF8String(packet.password, utf8Encoder));
        }
        var fixedHeader = [packetType << 4 | flags].concat(encodeLength(variableHeader.length + payload.length));
        return Uint8Array.from([].concat(fixedHeader, variableHeader, payload));
      }
      function decode(buffer, remainingStart, _remainingLength, utf8Decoder) {
        var protocolNameStart = remainingStart;
        var protocolName = decodeUTF8String(buffer, protocolNameStart, utf8Decoder);
        var protocolLevelIndex = protocolNameStart + protocolName.length;
        var protocolLevel = buffer[protocolLevelIndex];
        var connectFlagsIndex = protocolLevelIndex + 1;
        var connectFlags = buffer[connectFlagsIndex];
        var usernameFlag = !!(connectFlags & 128);
        var passwordFlag = !!(connectFlags & 64);
        var willRetain = !!(connectFlags & 32);
        var willQoS = (connectFlags & 16 + 8) >> 3;
        var willFlag = !!(connectFlags & 4);
        var cleanSession = !!(connectFlags & 2);
        if (willQoS !== 0 && willQoS !== 1 && willQoS !== 2) {
          throw new Error("invalid will qos");
        }
        var keepAliveIndex = connectFlagsIndex + 1;
        var keepAlive = (buffer[keepAliveIndex] << 8) + buffer[keepAliveIndex + 1];
        var clientIdStart = keepAliveIndex + 2;
        var clientId = decodeUTF8String(buffer, clientIdStart, utf8Decoder);
        var username;
        var password;
        var usernameStart = clientIdStart + clientId.length;
        if (usernameFlag) {
          username = decodeUTF8String(buffer, usernameStart, utf8Decoder);
        }
        if (passwordFlag) {
          var passwordStart = usernameStart + (username ? username.length : 0);
          password = decodeUTF8String(buffer, passwordStart, utf8Decoder);
        }
        return {
          type: "connect",
          protocolName: protocolName.value,
          protocolLevel: protocolLevel,
          clientId: clientId.value,
          username: username ? username.value : undefined,
          password: password ? password.value : undefined,
          will: willFlag ? {
            retain: willRetain,
            qos: willQoS
          } : undefined,
          clean: cleanSession,
          keepAlive: keepAlive
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/core.js", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _inheritsLoose, _construct, cclegacy;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _construct = module.construct;
    }, function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      var _ref, _ref2, _ref3, _ref4, _ref5;
      cclegacy._RF.push({}, "8381eP4KNxFfJ9EQxefgLVU", "core", undefined);
      /* eslint-disable no-use-before-define */

      var crypto = ((_ref = typeof globalThis != 'undefined' ? globalThis : void 0) == null ? void 0 : _ref.crypto) || ((_ref2 = typeof global != 'undefined' ? global : void 0) == null ? void 0 : _ref2.crypto) || ((_ref3 = typeof window != 'undefined' ? window : void 0) == null ? void 0 : _ref3.crypto) || ((_ref4 = typeof self != 'undefined' ? self : void 0) == null ? void 0 : _ref4.crypto) || ((_ref5 = typeof frames != 'undefined' ? frames : void 0) == null || (_ref5 = _ref5[0]) == null ? void 0 : _ref5.crypto);
      var randomWordArray;
      if (crypto) {
        randomWordArray = function randomWordArray(nBytes) {
          var words = [];
          for (var i = 0; i < nBytes; i += 4) {
            words.push(crypto.getRandomValues(new Uint32Array(1))[0]);
          }
          return new WordArray(words, nBytes);
        };
      } else {
        // Because there is no global crypto property in this context, cryptographically unsafe Math.random() is used.

        randomWordArray = function randomWordArray(nBytes) {
          var words = [];
          var r = function r(m_w) {
            var _m_w = m_w;
            var _m_z = 0x3ade68b1;
            var mask = 0xffffffff;
            return function () {
              _m_z = 0x9069 * (_m_z & 0xFFFF) + (_m_z >> 0x10) & mask;
              _m_w = 0x4650 * (_m_w & 0xFFFF) + (_m_w >> 0x10) & mask;
              var result = (_m_z << 0x10) + _m_w & mask;
              result /= 0x100000000;
              result += 0.5;
              return result * (Math.random() > 0.5 ? 1 : -1);
            };
          };
          for (var i = 0, rcache; i < nBytes; i += 4) {
            var _r = r((rcache || Math.random()) * 0x100000000);
            rcache = _r() * 0x3ade67b7;
            words.push(_r() * 0x100000000 | 0);
          }
          return new WordArray(words, nBytes);
        };
      }

      /**
       * Base class for inheritance.
       */
      var Base = exports('Base', /*#__PURE__*/function () {
        function Base() {}
        /**
         * Extends this object and runs the init method.
         * Arguments to create() will be passed to init().
         *
         * @return {Object} The new object.
         *
         * @static
         *
         * @example
         *
         *     var instance = MyType.create();
         */
        Base.create = function create() {
          for (var _len = arguments.length, args = new Array(_len), _key2 = 0; _key2 < _len; _key2++) {
            args[_key2] = arguments[_key2];
          }
          return _construct(this, args);
        }

        /**
         * Copies properties into this object.
         *
         * @param {Object} properties The properties to mix in.
         *
         * @example
         *
         *     MyType.mixIn({
         *         field: 'value'
         *     });
         */;
        var _proto = Base.prototype;
        _proto.mixIn = function mixIn(properties) {
          return Object.assign(this, properties);
        }

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = instance.clone();
         */;
        _proto.clone = function clone() {
          var clone = new this.constructor();
          Object.assign(clone, this);
          return clone;
        };
        return Base;
      }());

      /**
       * An array of 32-bit words.
       *
       * @property {Array} words The array of 32-bit words.
       * @property {number} sigBytes The number of significant bytes in this word array.
       */
      var WordArray = exports('WordArray', /*#__PURE__*/function (_Base) {
        _inheritsLoose(WordArray, _Base);
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of 32-bit words.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.create();
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
         */
        function WordArray(words, sigBytes) {
          var _this;
          if (words === void 0) {
            words = [];
          }
          if (sigBytes === void 0) {
            sigBytes = words.length * 4;
          }
          _this = _Base.call(this) || this;
          var typedArray = words;
          // Convert buffers to uint8
          if (typedArray instanceof ArrayBuffer) {
            typedArray = new Uint8Array(typedArray);
          }

          // Convert other array views to uint8
          if (typedArray instanceof Int8Array || typedArray instanceof Uint8ClampedArray || typedArray instanceof Int16Array || typedArray instanceof Uint16Array || typedArray instanceof Int32Array || typedArray instanceof Uint32Array || typedArray instanceof Float32Array || typedArray instanceof Float64Array) {
            typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
          }

          // Handle Uint8Array
          if (typedArray instanceof Uint8Array) {
            // Shortcut
            var typedArrayByteLength = typedArray.byteLength;

            // Extract bytes
            var _words = [];
            for (var i = 0; i < typedArrayByteLength; i += 1) {
              _words[i >>> 2] |= typedArray[i] << 24 - i % 4 * 8;
            }

            // Initialize this word array
            _this.words = _words;
            _this.sigBytes = typedArrayByteLength;
          } else {
            // Else call normal init
            _this.words = words;
            _this.sigBytes = sigBytes;
          }
          return _this;
        }

        /**
         * Creates a word array filled with random bytes.
         *
         * @param {number} nBytes The number of random bytes to generate.
         *
         * @return {WordArray} The random word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.lib.WordArray.random(16);
         */
        var _proto2 = WordArray.prototype;
        /**
         * Converts this word array to a string.
         *
         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
         *
         * @return {string} The stringified word array.
         *
         * @example
         *
         *     var string = wordArray + '';
         *     var string = wordArray.toString();
         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
         */
        _proto2.toString = function toString(encoder) {
          if (encoder === void 0) {
            encoder = Hex;
          }
          return encoder.stringify(this);
        }

        /**
         * Concatenates a word array to this word array.
         *
         * @param {WordArray} wordArray The word array to append.
         *
         * @return {WordArray} This word array.
         *
         * @example
         *
         *     wordArray1.concat(wordArray2);
         */;
        _proto2.concat = function concat(wordArray) {
          // Shortcuts
          var thisWords = this.words;
          var thatWords = wordArray.words;
          var thisSigBytes = this.sigBytes;
          var thatSigBytes = wordArray.sigBytes;

          // Clamp excess bits
          this.clamp();

          // Concat
          if (thisSigBytes % 4) {
            // Copy one byte at a time
            for (var i = 0; i < thatSigBytes; i += 1) {
              var thatByte = thatWords[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
              thisWords[thisSigBytes + i >>> 2] |= thatByte << 24 - (thisSigBytes + i) % 4 * 8;
            }
          } else {
            // Copy one word at a time
            for (var _i = 0; _i < thatSigBytes; _i += 4) {
              thisWords[thisSigBytes + _i >>> 2] = thatWords[_i >>> 2];
            }
          }
          this.sigBytes += thatSigBytes;

          // Chainable
          return this;
        }

        /**
         * Removes insignificant bits.
         *
         * @example
         *
         *     wordArray.clamp();
         */;
        _proto2.clamp = function clamp() {
          // Shortcuts
          var words = this.words,
            sigBytes = this.sigBytes;

          // Clamp
          words[sigBytes >>> 2] &= 0xffffffff << 32 - sigBytes % 4 * 8;
          words.length = Math.ceil(sigBytes / 4);
        }

        /**
         * Creates a copy of this word array.
         *
         * @return {WordArray} The clone.
         *
         * @example
         *
         *     var clone = wordArray.clone();
         */;
        _proto2.clone = function clone() {
          var clone = _Base.prototype.clone.call(this);
          clone.words = this.words.slice(0);
          return clone;
        };
        return WordArray;
      }(Base));

      /**
       * Hex encoding strategy.
       */
      WordArray.random = randomWordArray;
      var Hex = exports('Hex', {
        /**
         * Converts a word array to a hex string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The hex string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var hexChars = [];
          for (var i = 0; i < sigBytes; i += 1) {
            var bite = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            hexChars.push((bite >>> 4).toString(16));
            hexChars.push((bite & 0x0f).toString(16));
          }
          return hexChars.join('');
        },
        /**
         * Converts a hex string to a word array.
         *
         * @param {string} hexStr The hex string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
         */
        parse: function parse(hexStr) {
          // Shortcut
          var hexStrLength = hexStr.length;

          // Convert
          var words = [];
          for (var i = 0; i < hexStrLength; i += 2) {
            words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << 24 - i % 8 * 4;
          }
          return new WordArray(words, hexStrLength / 2);
        }
      });

      /**
       * Latin1 encoding strategy.
       */
      var Latin1 = exports('Latin1', {
        /**
         * Converts a word array to a Latin1 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Latin1 string.
         *
         * @static
         *
         * @example
         *
         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var latin1Chars = [];
          for (var i = 0; i < sigBytes; i += 1) {
            var bite = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            latin1Chars.push(String.fromCharCode(bite));
          }
          return latin1Chars.join('');
        },
        /**
         * Converts a Latin1 string to a word array.
         *
         * @param {string} latin1Str The Latin1 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
         */
        parse: function parse(latin1Str) {
          // Shortcut
          var latin1StrLength = latin1Str.length;

          // Convert
          var words = [];
          for (var i = 0; i < latin1StrLength; i += 1) {
            words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << 24 - i % 4 * 8;
          }
          return new WordArray(words, latin1StrLength);
        }
      });

      /**
       * UTF-8 encoding strategy.
       */
      var Utf8 = exports('Utf8', {
        /**
         * Converts a word array to a UTF-8 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-8 string.
         *
         * @static
         *
         * @example
         *
         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          try {
            return decodeURIComponent(escape(Latin1.stringify(wordArray)));
          } catch (e) {
            throw new Error('Malformed UTF-8 data');
          }
        },
        /**
         * Converts a UTF-8 string to a word array.
         *
         * @param {string} utf8Str The UTF-8 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
         */
        parse: function parse(utf8Str) {
          return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
        }
      });

      /**
       * Abstract buffered block algorithm template.
       *
       * The property blockSize must be implemented in a concrete subtype.
       *
       * @property {number} _minBufferSize
       *
       *     The number of blocks that should be kept unprocessed in the buffer. Default: 0
       */
      var BufferedBlockAlgorithm = exports('BufferedBlockAlgorithm', /*#__PURE__*/function (_Base2) {
        _inheritsLoose(BufferedBlockAlgorithm, _Base2);
        function BufferedBlockAlgorithm() {
          var _this2;
          _this2 = _Base2.call(this) || this;
          _this2._minBufferSize = 0;
          return _this2;
        }

        /**
         * Resets this block algorithm's data buffer to its initial state.
         *
         * @example
         *
         *     bufferedBlockAlgorithm.reset();
         */
        var _proto3 = BufferedBlockAlgorithm.prototype;
        _proto3.reset = function reset() {
          // Initial values
          this._data = new WordArray();
          this._nDataBytes = 0;
        }

        /**
         * Adds new data to this block algorithm's buffer.
         *
         * @param {WordArray|string} data
         *
         *     The data to append. Strings are converted to a WordArray using UTF-8.
         *
         * @example
         *
         *     bufferedBlockAlgorithm._append('data');
         *     bufferedBlockAlgorithm._append(wordArray);
         */;
        _proto3._append = function _append(data) {
          var m_data = data;

          // Convert string to WordArray, else assume WordArray already
          if (typeof m_data === 'string') {
            m_data = Utf8.parse(m_data);
          }

          // Append
          this._data.concat(m_data);
          this._nDataBytes += m_data.sigBytes;
        }

        /**
         * Processes available data blocks.
         *
         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
         *
         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
         *
         * @return {WordArray} The processed data.
         *
         * @example
         *
         *     var processedData = bufferedBlockAlgorithm._process();
         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
         */;
        _proto3._process = function _process(doFlush) {
          var processedWords;

          // Shortcuts
          var data = this._data,
            blockSize = this.blockSize;
          var dataWords = data.words;
          var dataSigBytes = data.sigBytes;
          var blockSizeBytes = blockSize * 4;

          // Count blocks ready
          var nBlocksReady = dataSigBytes / blockSizeBytes;
          if (doFlush) {
            // Round up to include partial blocks
            nBlocksReady = Math.ceil(nBlocksReady);
          } else {
            // Round down to include only full blocks,
            // less the number of blocks that must remain in the buffer
            nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
          }

          // Count words ready
          var nWordsReady = nBlocksReady * blockSize;

          // Count bytes ready
          var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

          // Process blocks
          if (nWordsReady) {
            for (var offset = 0; offset < nWordsReady; offset += blockSize) {
              // Perform concrete-algorithm logic
              this._doProcessBlock(dataWords, offset);
            }

            // Remove processed words
            processedWords = dataWords.splice(0, nWordsReady);
            data.sigBytes -= nBytesReady;
          }

          // Return processed words
          return new WordArray(processedWords, nBytesReady);
        }

        /**
         * Creates a copy of this object.
         *
         * @return {Object} The clone.
         *
         * @example
         *
         *     var clone = bufferedBlockAlgorithm.clone();
         */;
        _proto3.clone = function clone() {
          var clone = _Base2.prototype.clone.call(this);
          clone._data = this._data.clone();
          return clone;
        };
        return BufferedBlockAlgorithm;
      }(Base));

      /**
       * Abstract hasher template.
       *
       * @property {number} blockSize
       *
       *     The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
       */
      var Hasher = exports('Hasher', /*#__PURE__*/function (_BufferedBlockAlgorit) {
        _inheritsLoose(Hasher, _BufferedBlockAlgorit);
        function Hasher(cfg) {
          var _this3;
          _this3 = _BufferedBlockAlgorit.call(this) || this;
          _this3.blockSize = 512 / 32;

          /**
           * Configuration options.
           */
          _this3.cfg = Object.assign(new Base(), cfg);

          // Set initial values
          _this3.reset();
          return _this3;
        }

        /**
         * Creates a shortcut function to a hasher's object interface.
         *
         * @param {Hasher} SubHasher The hasher to create a helper for.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
         */
        Hasher._createHelper = function _createHelper(SubHasher) {
          return function (message, cfg) {
            return new SubHasher(cfg).finalize(message);
          };
        }

        /**
         * Creates a shortcut function to the HMAC's object interface.
         *
         * @param {Hasher} SubHasher The hasher to use in this HMAC helper.
         *
         * @return {Function} The shortcut function.
         *
         * @static
         *
         * @example
         *
         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
         */;
        Hasher._createHmacHelper = function _createHmacHelper(SubHasher) {
          return function (message, key) {
            return new HMAC(SubHasher, key).finalize(message);
          };
        }

        /**
         * Resets this hasher to its initial state.
         *
         * @example
         *
         *     hasher.reset();
         */;
        var _proto4 = Hasher.prototype;
        _proto4.reset = function reset() {
          // Reset data buffer
          _BufferedBlockAlgorit.prototype.reset.call(this);

          // Perform concrete-hasher logic
          this._doReset();
        }

        /**
         * Updates this hasher with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {Hasher} This hasher.
         *
         * @example
         *
         *     hasher.update('message');
         *     hasher.update(wordArray);
         */;
        _proto4.update = function update(messageUpdate) {
          // Append
          this._append(messageUpdate);

          // Update the hash
          this._process();

          // Chainable
          return this;
        }

        /**
         * Finalizes the hash computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The hash.
         *
         * @example
         *
         *     var hash = hasher.finalize();
         *     var hash = hasher.finalize('message');
         *     var hash = hasher.finalize(wordArray);
         */;
        _proto4.finalize = function finalize(messageUpdate) {
          // Final message update
          if (messageUpdate) {
            this._append(messageUpdate);
          }

          // Perform concrete-hasher logic
          var hash = this._doFinalize();
          return hash;
        };
        return Hasher;
      }(BufferedBlockAlgorithm));

      /**
       * HMAC algorithm.
       */
      var HMAC = exports('HMAC', /*#__PURE__*/function (_Base3) {
        _inheritsLoose(HMAC, _Base3);
        /**
         * Initializes a newly created HMAC.
         *
         * @param {Hasher} SubHasher The hash algorithm to use.
         * @param {WordArray|string} key The secret key.
         *
         * @example
         *
         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
         */
        function HMAC(SubHasher, key) {
          var _this4;
          _this4 = _Base3.call(this) || this;
          var hasher = new SubHasher();
          _this4._hasher = hasher;

          // Convert string to WordArray, else assume WordArray already
          var _key = key;
          if (typeof _key === 'string') {
            _key = Utf8.parse(_key);
          }

          // Shortcuts
          var hasherBlockSize = hasher.blockSize;
          var hasherBlockSizeBytes = hasherBlockSize * 4;

          // Allow arbitrary length keys
          if (_key.sigBytes > hasherBlockSizeBytes) {
            _key = hasher.finalize(key);
          }

          // Clamp excess bits
          _key.clamp();

          // Clone key for inner and outer pads
          var oKey = _key.clone();
          _this4._oKey = oKey;
          var iKey = _key.clone();
          _this4._iKey = iKey;

          // Shortcuts
          var oKeyWords = oKey.words;
          var iKeyWords = iKey.words;

          // XOR keys with pad constants
          for (var i = 0; i < hasherBlockSize; i += 1) {
            oKeyWords[i] ^= 0x5c5c5c5c;
            iKeyWords[i] ^= 0x36363636;
          }
          oKey.sigBytes = hasherBlockSizeBytes;
          iKey.sigBytes = hasherBlockSizeBytes;

          // Set initial values
          _this4.reset();
          return _this4;
        }

        /**
         * Resets this HMAC to its initial state.
         *
         * @example
         *
         *     hmacHasher.reset();
         */
        var _proto5 = HMAC.prototype;
        _proto5.reset = function reset() {
          // Shortcut
          var hasher = this._hasher;

          // Reset
          hasher.reset();
          hasher.update(this._iKey);
        }

        /**
         * Updates this HMAC with a message.
         *
         * @param {WordArray|string} messageUpdate The message to append.
         *
         * @return {HMAC} This HMAC instance.
         *
         * @example
         *
         *     hmacHasher.update('message');
         *     hmacHasher.update(wordArray);
         */;
        _proto5.update = function update(messageUpdate) {
          this._hasher.update(messageUpdate);

          // Chainable
          return this;
        }

        /**
         * Finalizes the HMAC computation.
         * Note that the finalize operation is effectively a destructive, read-once operation.
         *
         * @param {WordArray|string} messageUpdate (Optional) A final message update.
         *
         * @return {WordArray} The HMAC.
         *
         * @example
         *
         *     var hmac = hmacHasher.finalize();
         *     var hmac = hmacHasher.finalize('message');
         *     var hmac = hmacHasher.finalize(wordArray);
         */;
        _proto5.finalize = function finalize(messageUpdate) {
          // Shortcut
          var hasher = this._hasher;

          // Compute HMAC
          var innerHash = hasher.finalize(messageUpdate);
          hasher.reset();
          var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));
          return hmac;
        };
        return HMAC;
      }(Base));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/CreateFileSprite.ts", ['cc'], function (exports) {
  var cclegacy, ImageAsset, Texture2D, SpriteFrame, Size;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
      ImageAsset = module.ImageAsset;
      Texture2D = module.Texture2D;
      SpriteFrame = module.SpriteFrame;
      Size = module.Size;
    }],
    execute: function () {
      cclegacy._RF.push({}, "cd428ngTsBMEIoB03xS9Nel", "CreateFileSprite", undefined);
      var CreateFileSprite = exports('default', /*#__PURE__*/function () {
        function CreateFileSprite(_callback, _error) {
          this.AcceptImgFormat = ['image/gif', 'image/jpeg', 'image/png', 'image/bmp'];
          this.callback = void 0;
          this.errorback = void 0;
          this.file = void 0;
          this.setLimitSize = 5;
          this.callback = _callback;
          this.errorback = _error;
          if (document.getElementById('inputfile') != null) {
            document.getElementById('inputfile').remove();
          }
          var input = document.createElement('input');
          input.type = "file";
          input.accept = "image/*";
          input.id = "inputfile";
          input.click();
          input.addEventListener("change", this.checkSpriteData.bind(this), false);
          document.head.appendChild(input);
        }
        var _proto = CreateFileSprite.prototype;
        _proto.checkSpriteData = function checkSpriteData(e) {
          var limitSize = this.setLimitSize * 1024 * 1024;
          this.file = e.target.files[0];
          console.log(this.file);
          if (this.AcceptImgFormat.indexOf(this.file.type) == -1) {
            this.errorback("044");
            return;
          }
          if (this.file.size > limitSize) {
            this.errorback("043");
            return;
          }
          if (!this.file) {
            this.errorback("045");
            return;
          }
          /**開一條支線傳給後端 */
          var reader = new FileReader();
          reader.onload = this.readerOnload.bind(this);
          reader.readAsDataURL(this.file);
        };
        _proto.readerOnload = function readerOnload(e) {
          var _this = this;
          var image = new Image();
          var data = e.target.result;
          image.src = data;
          // let _base64 = data.split(",")[1]
          image.onload = function () {
            var imgAsset = new ImageAsset(); //重置此图像资源使用的原始图像源
            imgAsset.reset(image);
            var texture = new Texture2D();
            texture.image = imgAsset;
            var sp = new SpriteFrame();
            //sprite 图片
            sp.texture = texture;
            // console.log(this.file);
            _this.callback(sp, _this.file);
            return;
          };
        }

        /**以下暫時用不到，如果需要進一步處理圖片才需要 */
        /**以下暫時用不到，如果需要進一步處理圖片才需要 */
        /**以下暫時用不到，如果需要進一步處理圖片才需要 */
        /**以下暫時用不到，如果需要進一步處理圖片才需要 */
        /**以下暫時用不到，如果需要進一步處理圖片才需要 */
        /**以下暫時用不到，如果需要進一步處理圖片才需要 */
        /**以下暫時用不到，如果需要進一步處理圖片才需要 */;
        _proto.dataURLtoFile = function dataURLtoFile(dataurl, filename) {
          //將base64轉換為檔案
          var arr = dataurl.split(','),
            mime = arr[0].match(/:(.*?);/),
            bstr = atob(arr[1]),
            n = bstr.length,
            u8arr = new Uint8Array(n);
          while (n--) {
            u8arr[n] = bstr.charCodeAt(n);
          }
          return new File([u8arr], filename, {
            //@ts-ignore
            type: mime
          });
        };
        _proto.compress = function compress(img) {
          // 用於壓縮圖片的canvas
          var canvas = document.createElement('canvas');
          var ctx = canvas.getContext('2d');
          // 瓦片canvas
          var tCanvas = document.createElement('canvas');
          var tctx = tCanvas.getContext('2d');
          var initSize = img.src.length;

          // 獲取父元素寬高
          var wid = 207;
          var hei = 207;
          // let parentWh = $('.creater_class .files');
          // let wid = parentWh.width();
          // let hei = parentWh.height();
          //console.log("父親:"+wid+'...'+hei)
          console.log("原始圖片:" + img.width + '...' + img.height);
          // 等比壓縮圖片
          var spec = this.AutoSize(img, wid, hei);
          var width = spec.width;
          var height = spec.height;
          console.log("變小圖片:" + width + '...' + height);
          // 如果圖片大於四百萬畫素，計算壓縮比並將大小壓至400萬以下
          var ratio;
          if ((ratio = width * height / 4000000) > 1) {
            ratio = Math.sqrt(ratio);
            width /= ratio;
            height /= ratio;
          } else {
            ratio = 1;
          }
          canvas.width = width;
          canvas.height = height;
          // 鋪底色
          ctx.fillStyle = '#000';
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          // 如果圖片畫素大於100萬則使用瓦片繪製
          var count;
          if ((count = width * height / 1000000) > 1) {
            count = ~~(Math.sqrt(count) + 1); // 計算要分成多少塊瓦片
            // 計算每塊瓦片的寬和高
            var nw = ~~(width / count);
            var nh = ~~(height / count);
            tCanvas.width = nw;
            tCanvas.height = nh;
            for (var i = 0; i < count; i++) {
              for (var j = 0; j < count; j++) {
                tctx.drawImage(img, i * nw * ratio, j * nh * ratio, nw * ratio, nh * ratio, 0, 0, nw, nh);
                ctx.drawImage(tCanvas, i * nw, j * nh, nw, nh);
              }
            }
          } else {
            ctx.drawImage(img, 0, 0, width, height);
          }

          // 進行最小壓縮0.1
          //var ndata = canvas.toDataURL('image/jpeg', 0.5);
          var ndata = canvas.toDataURL();
          // console.log('壓縮前：' + initSize)
          // console.log('壓縮後：' + ndata.length)
          // console.log('壓縮率：' + ~~(100 * (initSize - ndata.length) / initSize) + "%")
          //tCanvas.width = tCanvas.height = canvas.width = canvas.height = 0;
          return ndata;
        };
        _proto.AutoSize = function AutoSize(image, maxWidth, maxHeight) {
          // 等比壓縮圖片
          var spec = new Size();
          // 當圖片比圖片框小時不做任何改變
          if (image.width < maxWidth && image.height < maxHeight) {
            //原圖片寬高比例 大於 圖片框寬高比例
            //寬大於高
            if (image.width >= image.height) {
              spec.width = maxWidth;
              spec.height = image.height * (maxWidth / image.width);
            }
            //高大於寬
            else {
              spec.width = image.width * (maxHeight / image.height);
              spec.height = maxHeight;
            }
            // spec.width = image.width;
            // spec.height = image.height;
          } else {
            //原圖片寬高比例 大於 圖片框寬高比例,則以框的寬為標準縮放，反之以框的高為標準縮放
            if (maxWidth / maxHeight <= image.width / image.height) {
              spec.width = maxWidth; //以框的寬度為標準
              spec.height = maxWidth * (image.height / image.width);
            } else {
              spec.width = maxHeight * (image.width / image.height);
              spec.height = maxHeight; //以框的高度為標準
            }
          }

          return spec;
        };
        return CreateFileSprite;
      }()); // _doChangePhoto() {
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/crypto_key.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        checkEncCryptoKey: checkEncCryptoKey,
        checkSigCryptoKey: checkSigCryptoKey
      });
      cclegacy._RF.push({}, "d47f1SpffJKFZOphV7dcOdM", "crypto_key", undefined);
      function unusable(name, prop) {
        if (prop === void 0) {
          prop = 'algorithm.name';
        }
        return new TypeError("CryptoKey does not support this operation, its " + prop + " must be " + name);
      }
      function isAlgorithm(algorithm, name) {
        return algorithm.name === name;
      }
      function getHashLength(hash) {
        return parseInt(hash.name.slice(4), 10);
      }
      function getNamedCurve(alg) {
        switch (alg) {
          case 'ES256':
            return 'P-256';
          case 'ES384':
            return 'P-384';
          case 'ES512':
            return 'P-521';
          default:
            throw new Error('unreachable');
        }
      }
      function checkUsage(key, usages) {
        if (usages.length && !usages.some(function (expected) {
          return key.usages.includes(expected);
        })) {
          var msg = 'CryptoKey does not support this operation, its usages must include ';
          if (usages.length > 2) {
            var last = usages.pop();
            msg += "one of " + usages.join(', ') + ", or " + last + ".";
          } else if (usages.length === 2) {
            msg += "one of " + usages[0] + " or " + usages[1] + ".";
          } else {
            msg += usages[0] + ".";
          }
          throw new TypeError(msg);
        }
      }
      function checkSigCryptoKey(key, alg) {
        switch (alg) {
          case 'HS256':
          case 'HS384':
          case 'HS512':
            {
              if (!isAlgorithm(key.algorithm, 'HMAC')) throw unusable('HMAC');
              var expected = parseInt(alg.slice(2), 10);
              var actual = getHashLength(key.algorithm.hash);
              if (actual !== expected) throw unusable("SHA-" + expected, 'algorithm.hash');
              break;
            }
          case 'RS256':
          case 'RS384':
          case 'RS512':
            {
              if (!isAlgorithm(key.algorithm, 'RSASSA-PKCS1-v1_5')) throw unusable('RSASSA-PKCS1-v1_5');
              var _expected = parseInt(alg.slice(2), 10);
              var _actual = getHashLength(key.algorithm.hash);
              if (_actual !== _expected) throw unusable("SHA-" + _expected, 'algorithm.hash');
              break;
            }
          case 'PS256':
          case 'PS384':
          case 'PS512':
            {
              if (!isAlgorithm(key.algorithm, 'RSA-PSS')) throw unusable('RSA-PSS');
              var _expected2 = parseInt(alg.slice(2), 10);
              var _actual2 = getHashLength(key.algorithm.hash);
              if (_actual2 !== _expected2) throw unusable("SHA-" + _expected2, 'algorithm.hash');
              break;
            }
          case 'EdDSA':
            {
              if (key.algorithm.name !== 'Ed25519' && key.algorithm.name !== 'Ed448') {
                throw unusable('Ed25519 or Ed448');
              }
              break;
            }
          case 'ES256':
          case 'ES384':
          case 'ES512':
            {
              if (!isAlgorithm(key.algorithm, 'ECDSA')) throw unusable('ECDSA');
              var _expected3 = getNamedCurve(alg);
              var _actual3 = key.algorithm.namedCurve;
              if (_actual3 !== _expected3) throw unusable(_expected3, 'algorithm.namedCurve');
              break;
            }
          default:
            throw new TypeError('CryptoKey does not support this operation');
        }
        for (var _len = arguments.length, usages = new Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) {
          usages[_key - 2] = arguments[_key];
        }
        checkUsage(key, usages);
      }
      function checkEncCryptoKey(key, alg) {
        switch (alg) {
          case 'A128GCM':
          case 'A192GCM':
          case 'A256GCM':
            {
              if (!isAlgorithm(key.algorithm, 'AES-GCM')) throw unusable('AES-GCM');
              var expected = parseInt(alg.slice(1, 4), 10);
              var actual = key.algorithm.length;
              if (actual !== expected) throw unusable(expected, 'algorithm.length');
              break;
            }
          case 'A128KW':
          case 'A192KW':
          case 'A256KW':
            {
              if (!isAlgorithm(key.algorithm, 'AES-KW')) throw unusable('AES-KW');
              var _expected4 = parseInt(alg.slice(1, 4), 10);
              var _actual4 = key.algorithm.length;
              if (_actual4 !== _expected4) throw unusable(_expected4, 'algorithm.length');
              break;
            }
          case 'ECDH':
            {
              switch (key.algorithm.name) {
                case 'ECDH':
                case 'X25519':
                case 'X448':
                  break;
                default:
                  throw unusable('ECDH, X25519, or X448');
              }
              break;
            }
          case 'PBES2-HS256+A128KW':
          case 'PBES2-HS384+A192KW':
          case 'PBES2-HS512+A256KW':
            if (!isAlgorithm(key.algorithm, 'PBKDF2')) throw unusable('PBKDF2');
            break;
          case 'RSA-OAEP':
          case 'RSA-OAEP-256':
          case 'RSA-OAEP-384':
          case 'RSA-OAEP-512':
            {
              if (!isAlgorithm(key.algorithm, 'RSA-OAEP')) throw unusable('RSA-OAEP');
              var _expected5 = parseInt(alg.slice(9), 10) || 1;
              var _actual5 = getHashLength(key.algorithm.hash);
              if (_actual5 !== _expected5) throw unusable("SHA-" + _expected5, 'algorithm.hash');
              break;
            }
          default:
            throw new TypeError('CryptoKey does not support this operation');
        }
        for (var _len2 = arguments.length, usages = new Array(_len2 > 2 ? _len2 - 2 : 0), _key2 = 2; _key2 < _len2; _key2++) {
          usages[_key2 - 2] = arguments[_key2];
        }
        checkUsage(key, usages);
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/CustomEvent.ts", ['cc', './Public.ts'], function (exports) {
  var cclegacy, EventHandler, js, Plug;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
      EventHandler = module.EventHandler;
      js = module.js;
    }, function (module) {
      Plug = module.Plug;
    }],
    execute: function () {
      cclegacy._RF.push({}, "6e38bngftZGf7tTIm6c3+UL", "CustomEvent", undefined);
      var CEType = exports('CEType', /*#__PURE__*/function (CEType) {
        CEType["ClickEvents"] = "clickEvents";
        CEType["CheckEvents"] = "checkEvents";
        return CEType;
      }({}));
      /**
       * 可與Button、Toggle、
       */
      var CustomEvent = /*#__PURE__*/function () {
        function CustomEvent() {}
        var _proto = CustomEvent.prototype;
        _proto.addEvent = function addEvent(type, componentTarget, callBack, target, customEventData) {
          if (this.findEvent(type, target, callBack)) this.removeEvent(type, target, callBack);
          var event = new EventHandler();
          event.target = componentTarget.node;
          event.component = js.getClassName(componentTarget);
          if (Plug.Model.checkStringNull(callBack)) throw new Error("484忘記給function@setFunctionName");
          event.handler = callBack;
          if (customEventData) event.customEventData = customEventData;
          target[type].push(event);
        };
        _proto.findEvent = function findEvent(type, target, callBack) {
          var isFind = false;
          var eventArr = target[type];
          for (var index = 0; index < eventArr.length; index++) {
            if (eventArr[index].handler == callBack) return isFind = true;
          }
          return isFind;
        };
        _proto.checkEvent = function checkEvent(type, target) {
          var eventArr = target[type];
          if (eventArr.length > 0) return true;
        };
        _proto.removeEvent = function removeEvent(type, target, callBack) {
          var eventArr = target[type];
          for (var index = 0; index < eventArr.length; index++) {
            if (eventArr[index].handler == callBack) return eventArr.splice(index);
          }
        };
        _proto.clearEvent = function clearEvent(type, target) {
          var eventArr = target[type];
          var count = eventArr.length - 1;
          for (var index = count; 0 < eventArr.length; index++) {
            eventArr.splice(index);
          }
        };
        return CustomEvent;
      }();
      var CustomEvent$1 = exports('default', new CustomEvent());
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/DelayTime.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseSingleton.ts'], function (exports) {
  var _inheritsLoose, _asyncToGenerator, _regeneratorRuntime, cclegacy, BaseSingleton;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BaseSingleton = module.default;
    }],
    execute: function () {
      cclegacy._RF.push({}, "41825AAalFDrL2dtEafzKIz", "DelayTime", undefined);
      //#endregion
      var DelayTime = exports('default', /*#__PURE__*/function (_BaseSingleton) {
        _inheritsLoose(DelayTime, _BaseSingleton);
        function DelayTime() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseSingleton.call.apply(_BaseSingleton, [this].concat(args)) || this;
          _this.connetDelay = [];
          _this.HeartrateNum = 0;
          return _this;
        }
        var _proto = DelayTime.prototype;
        _proto.StartDT = /*#__PURE__*/function () {
          var _StartDT = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(_time) {
            var _this2 = this;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  return _context.abrupt("return", new Promise(function (resolve, reject) {
                    var DtID = setTimeout(function () {
                      resolve();
                      clearTimeout(DtID);
                      // for (let index = 0; index < this.connetDelay.length; index++) {
                      var index = _this2.connetDelay.indexOf(DtID);
                      if (index != -1) {
                        _this2.connetDelay.splice(index - 1, index);
                      }
                      // }
                    }, _time * 1000);
                    _this2.connetDelay.push(DtID);
                  }));
                case 1:
                case "end":
                  return _context.stop();
              }
            }, _callee);
          }));
          function StartDT(_x) {
            return _StartDT.apply(this, arguments);
          }
          return StartDT;
        }();
        _proto.StartDT_NotClear = /*#__PURE__*/function () {
          var _StartDT_NotClear = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee2(_time) {
            var _this3 = this;
            return _regeneratorRuntime().wrap(function _callee2$(_context2) {
              while (1) switch (_context2.prev = _context2.next) {
                case 0:
                  return _context2.abrupt("return", new Promise(function (resolve, reject) {
                    var DtID = setTimeout(function () {
                      resolve();
                      clearTimeout(DtID);
                      // for (let index = 0; index < this.connetDelay.length; index++) {
                      var index = _this3.connetDelay.indexOf(DtID);
                      if (index != -1) {
                        _this3.connetDelay.splice(index - 1, index);
                      }
                      // }
                    }, _time * 1000);
                  }));
                case 1:
                case "end":
                  return _context2.stop();
              }
            }, _callee2);
          }));
          function StartDT_NotClear(_x2) {
            return _StartDT_NotClear.apply(this, arguments);
          }
          return StartDT_NotClear;
        }();
        _proto.StopAllDT = function StopAllDT() {
          var count = this.connetDelay.length;
          for (var index = 0; index < count; index++) {
            var DtID = this.connetDelay.shift();
            clearTimeout(DtID);
          }
        };
        return DelayTime;
      }(BaseSingleton()));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/disconnect.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "6cdfdqaF7lIJbpOIbJ5YdAh", "disconnect", undefined);
      function encode(_packet) {
        var packetType = 14;
        var flags = 0;
        return Uint8Array.from([packetType << 4 | flags, 0]);
      }
      function decode(_buffer, _remainingStart, _remainingLength) {
        return {
          type: "disconnect"
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/EasyCode.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './AutoFollow.ts'], function (exports) {
  var _inheritsLoose, cclegacy, error, UITransform, Size, Component, AutoFollow, TheTarget;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      error = module.error;
      UITransform = module.UITransform;
      Size = module.Size;
      Component = module.Component;
    }, function (module) {
      AutoFollow = module.default;
      TheTarget = module.TheTarget;
    }],
    execute: function () {
      cclegacy._RF.push({}, "9a3fbZPX0ZAmadhjnGcmGkD", "EasyCode", undefined);
      var EasyCode = exports('default', /*#__PURE__*/function (_Component) {
        _inheritsLoose(EasyCode, _Component);
        function EasyCode() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          /**NodePoolManager.getInstance */
          _this.nameMap = new Map();
          /**有沒有從池裡拿 */
          _this.isGet = void 0;
          return _this;
        }
        var _proto = EasyCode.prototype;
        /**
         * 
         * @param node 要掛autoFollow的物件
         * @param content 掛好autoFollow的物件要移到底下的物件
         * @returns 
         */
        _proto.autoFollow = function autoFollow(node, content) {
          try {
            if (!node) return;
            if (node.getComponent(AutoFollow) == null && !node.getComponent(TheTarget)) node.addComponent(AutoFollow).createNewTarget();
            content.addChild(node);
          } catch (e) {
            error(e);
          }
          return;
        }
        /**
         * 
         * @param conNode 要設定的conNode
         * @param parent conNode要掛到底下的物件
         * @returns 
         */;
        _proto.setConNode = function setConNode(conNode, parent) {
          try {
            conNode.addComponent(UITransform).setContentSize(new Size(0, 0));
            parent.addChild(conNode);
          } catch (e) {
            error(e);
          }
          return;
        }
        /**
         * 用於紀錄重複生成的物件，會回傳keycount+1
         * @param keyname 自訂namemap索引詞綴
         * @param node 要索引的物件
         * @param keyCount 索引計數用
         * @returns 
         */;
        _proto.setMap = function setMap(keyname, node, keyCount) {
          // warn(`test:${keyname},${keyCount}`)
          this.nameMap.set(keyname + keyCount.toString(), node);
          keyCount++;
          return keyCount;
        }
        /**
         * 將nameMap中詞綴內帶有keyname的物件都放進池內
         * @param keyname namemap索引詞綴
         */
        // putInPool(keyname: string) {
        //     for (let i of this.nameMap.keys()) {
        //         if (i.includes(keyname)) {
        //             // warn(`回收${i}`)
        //             NodePoolManager.getInstance.put(this.nameMap.get(i), true)
        //             this.nameMap.delete(i)
        //         }
        //     }
        //     // for (let key = 0; this.nameMap.has(keyname + key); key++) {
        //     //     // warn(`test:put${}`)
        //     //     this.NPM.put(this.nameMap.get(keyname + key), true)
        //     //     this.nameMap.delete(keyname + key)
        //     // }
        // }
        ;

        return EasyCode;
      }(Component));
      var EasyString = exports('EasyString', /*#__PURE__*/function (EasyString) {
        EasyString["IOR"] = "itemOwnerRoom";
        EasyString["ILP"] = "itemLimitPage";
        return EasyString;
      }({}));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/EditSpine.js", ['./cjs-loader.mjs'], function (exports, module) {
  var loader;
  return {
    setters: [function (module) {
      loader = module.default;
    }],
    execute: function () {
      exports('default', void 0);
      var _cjsExports;
      var __cjsMetaURL = exports('__cjsMetaURL', module.meta.url);
      loader.define(__cjsMetaURL, function (exports$1, require, module, __filename, __dirname) {
        // #region ORIGINAL CODE

        /*jshint esversion: 6 */

        if (CC_EDITOR) {
          cc.internal.SpineSkeleton.prototype.update = null;
          cc.game.once(cc.Game.EVENT_ENGINE_INITED, function () {
            cc.js.mixin(cc.internal.SpineSkeleton.prototype, {
              update: function update(dt) {
                // if (this.paused) return;
                dt *= this._timeScale * 1.0;
                if (this.isAnimationCached()) {
                  // Cache mode and has animation queue.
                  if (this._isAniComplete) {
                    if (this._animationQueue.length === 0 && !this._headAniInfo) {
                      var frameCache = this._frameCache;
                      if (frameCache && frameCache.isInvalid()) {
                        frameCache.updateToFrame();
                        var frames = frameCache.frames;
                        this._curFrame = frames[frames.length - 1];
                      }
                      return;
                    }
                    if (!this._headAniInfo) {
                      this._headAniInfo = this._animationQueue.shift();
                    }
                    this._accTime += dt;
                    if (this._accTime > this._headAniInfo.delay) {
                      var aniInfo = this._headAniInfo;
                      this._headAniInfo = null;
                      this.setAnimation(0, aniInfo.animationName, aniInfo.loop);
                    }
                    return;
                  }
                  this._updateCache(dt);
                }
              }
            });
          });
        }

        // #endregion ORIGINAL CODE

        _cjsExports = exports('default', module.exports);
      }, {});
    }
  };
});

System.register("chunks:///_virtual/EditSpine.mjs_cjs=&original=.js", ['./EditSpine.js', './cjs-loader.mjs'], function (exports, module) {
  var __cjsMetaURL, loader;
  return {
    setters: [function (module) {
      __cjsMetaURL = module.__cjsMetaURL;
      var _setter = {};
      _setter.__cjsMetaURL = module.__cjsMetaURL;
      _setter.default = module.default;
      exports(_setter);
    }, function (module) {
      loader = module.default;
    }],
    execute: function () {
      // I am the facade module who provides access to the CommonJS module './EditSpine.js'~
      if (!__cjsMetaURL) {
        loader.throwInvalidWrapper('./EditSpine.js', module.meta.url);
      }
      loader.require(__cjsMetaURL);
    }
  };
});

System.register("chunks:///_virtual/enc-base64.js", ['cc', './core.js'], function (exports) {
  var cclegacy, WordArray;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
    }],
    execute: function () {
      cclegacy._RF.push({}, "33b0btOzutEP6cSC/pqFoYe", "enc-base64", undefined);
      var parseLoop = exports('parseLoop', function parseLoop(base64Str, base64StrLength, reverseMap) {
        var words = [];
        var nBytes = 0;
        for (var i = 0; i < base64StrLength; i += 1) {
          if (i % 4) {
            var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << i % 4 * 2;
            var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> 6 - i % 4 * 2;
            var bitsCombined = bits1 | bits2;
            words[nBytes >>> 2] |= bitsCombined << 24 - nBytes % 4 * 8;
            nBytes += 1;
          }
        }
        return WordArray.create(words, nBytes);
      });

      /**
       * Base64 encoding strategy.
       */
      var Base64 = exports('Base64', {
        /**
         * Converts a word array to a Base64 string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The Base64 string.
         *
         * @static
         *
         * @example
         *
         *     const base64String = CryptoJS.enc.Base64.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;
          var map = this._map;

          // Clamp excess bits
          wordArray.clamp();

          // Convert
          var base64Chars = [];
          for (var i = 0; i < sigBytes; i += 3) {
            var byte1 = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            var byte2 = words[i + 1 >>> 2] >>> 24 - (i + 1) % 4 * 8 & 0xff;
            var byte3 = words[i + 2 >>> 2] >>> 24 - (i + 2) % 4 * 8 & 0xff;
            var triplet = byte1 << 16 | byte2 << 8 | byte3;
            for (var j = 0; j < 4 && i + j * 0.75 < sigBytes; j += 1) {
              base64Chars.push(map.charAt(triplet >>> 6 * (3 - j) & 0x3f));
            }
          }

          // Add padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            while (base64Chars.length % 4) {
              base64Chars.push(paddingChar);
            }
          }
          return base64Chars.join('');
        },
        /**
         * Converts a Base64 string to a word array.
         *
         * @param {string} base64Str The Base64 string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Base64.parse(base64String);
         */
        parse: function parse(base64Str) {
          // Shortcuts
          var base64StrLength = base64Str.length;
          var map = this._map;
          var reverseMap = this._reverseMap;
          if (!reverseMap) {
            this._reverseMap = [];
            reverseMap = this._reverseMap;
            for (var j = 0; j < map.length; j += 1) {
              reverseMap[map.charCodeAt(j)] = j;
            }
          }

          // Ignore padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            var paddingIndex = base64Str.indexOf(paddingChar);
            if (paddingIndex !== -1) {
              base64StrLength = paddingIndex;
            }
          }

          // Convert
          return parseLoop(base64Str, base64StrLength, reverseMap);
        },
        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/enc-base64url.js", ['cc', './enc-base64.js'], function (exports) {
  var cclegacy, parseLoop;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      parseLoop = module.parseLoop;
    }],
    execute: function () {
      cclegacy._RF.push({}, "8f97982vy1Kx5NBp8RyZ8tV", "enc-base64url", undefined);

      /**
       * Base64url encoding strategy.
       */
      var Base64url = exports('Base64url', {
        /**
         * Converts a word array to a Base64url string.
         *
         * @param {WordArray} wordArray The word array.
         * 
         * @param {boolean} urlSafe Whether to use url safe.
         *
         * @return {string} The Base64url string.
         *
         * @static
         *
         * @example
         *
         *     const base64String = CryptoJS.enc.Base64.stringify(wordArray);
         */
        stringify: function stringify(wordArray, urlSafe) {
          if (urlSafe === void 0) {
            urlSafe = true;
          }
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;
          var map = urlSafe ? this._safeMap : this._map;

          // Clamp excess bits
          wordArray.clamp();

          // Convert
          var base64Chars = [];
          for (var i = 0; i < sigBytes; i += 3) {
            var byte1 = words[i >>> 2] >>> 24 - i % 4 * 8 & 0xff;
            var byte2 = words[i + 1 >>> 2] >>> 24 - (i + 1) % 4 * 8 & 0xff;
            var byte3 = words[i + 2 >>> 2] >>> 24 - (i + 2) % 4 * 8 & 0xff;
            var triplet = byte1 << 16 | byte2 << 8 | byte3;
            for (var j = 0; j < 4 && i + j * 0.75 < sigBytes; j += 1) {
              base64Chars.push(map.charAt(triplet >>> 6 * (3 - j) & 0x3f));
            }
          }

          // Add padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            while (base64Chars.length % 4) {
              base64Chars.push(paddingChar);
            }
          }
          return base64Chars.join('');
        },
        /**
         * Converts a Base64url string to a word array.
         *
         * @param {string} base64Str The Base64url string.
         * 
         * @param {boolean} urlSafe Whether to use url safe.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Base64.parse(base64String);
         */
        parse: function parse(base64Str, urlSafe) {
          if (urlSafe === void 0) {
            urlSafe = true;
          }
          // Shortcuts
          var base64StrLength = base64Str.length;
          var map = urlSafe ? this._safeMap : this._map;
          var reverseMap = this._reverseMap;
          if (!reverseMap) {
            this._reverseMap = [];
            reverseMap = this._reverseMap;
            for (var j = 0; j < map.length; j += 1) {
              reverseMap[map.charCodeAt(j)] = j;
            }
          }

          // Ignore padding
          var paddingChar = map.charAt(64);
          if (paddingChar) {
            var paddingIndex = base64Str.indexOf(paddingChar);
            if (paddingIndex !== -1) {
              base64StrLength = paddingIndex;
            }
          }

          // Convert
          return parseLoop(base64Str, base64StrLength, reverseMap);
        },
        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
        _safeMap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/enc-utf16.js", ['cc', './core.js'], function (exports) {
  var cclegacy, WordArray;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
    }],
    execute: function () {
      cclegacy._RF.push({}, "14fcaTLE0FEGaYK2l44urka", "enc-utf16", undefined);
      var swapEndian = function swapEndian(word) {
        return word << 8 & 0xff00ff00 | word >>> 8 & 0x00ff00ff;
      };

      /**
       * UTF-16 BE encoding strategy.
       */
      var Utf16BE = exports('Utf16BE', {
        /**
         * Converts a word array to a UTF-16 BE string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-16 BE string.
         *
         * @static
         *
         * @example
         *
         *     const utf16String = CryptoJS.enc.Utf16.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var utf16Chars = [];
          for (var i = 0; i < sigBytes; i += 2) {
            var codePoint = words[i >>> 2] >>> 16 - i % 4 * 8 & 0xffff;
            utf16Chars.push(String.fromCharCode(codePoint));
          }
          return utf16Chars.join('');
        },
        /**
         * Converts a UTF-16 BE string to a word array.
         *
         * @param {string} utf16Str The UTF-16 BE string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Utf16.parse(utf16String);
         */
        parse: function parse(utf16Str) {
          // Shortcut
          var utf16StrLength = utf16Str.length;

          // Convert
          var words = [];
          for (var i = 0; i < utf16StrLength; i += 1) {
            words[i >>> 1] |= utf16Str.charCodeAt(i) << 16 - i % 2 * 16;
          }
          return WordArray.create(words, utf16StrLength * 2);
        }
      });
      var Utf16 = exports('Utf16', Utf16BE);

      /**
       * UTF-16 LE encoding strategy.
       */
      var Utf16LE = exports('Utf16LE', {
        /**
         * Converts a word array to a UTF-16 LE string.
         *
         * @param {WordArray} wordArray The word array.
         *
         * @return {string} The UTF-16 LE string.
         *
         * @static
         *
         * @example
         *
         *     const utf16Str = CryptoJS.enc.Utf16LE.stringify(wordArray);
         */
        stringify: function stringify(wordArray) {
          // Shortcuts
          var words = wordArray.words,
            sigBytes = wordArray.sigBytes;

          // Convert
          var utf16Chars = [];
          for (var i = 0; i < sigBytes; i += 2) {
            var codePoint = swapEndian(words[i >>> 2] >>> 16 - i % 4 * 8 & 0xffff);
            utf16Chars.push(String.fromCharCode(codePoint));
          }
          return utf16Chars.join('');
        },
        /**
         * Converts a UTF-16 LE string to a word array.
         *
         * @param {string} utf16Str The UTF-16 LE string.
         *
         * @return {WordArray} The word array.
         *
         * @static
         *
         * @example
         *
         *     const wordArray = CryptoJS.enc.Utf16LE.parse(utf16Str);
         */
        parse: function parse(utf16Str) {
          // Shortcut
          var utf16StrLength = utf16Str.length;

          // Convert
          var words = [];
          for (var i = 0; i < utf16StrLength; i += 1) {
            words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << 16 - i % 2 * 16);
          }
          return WordArray.create(words, utf16StrLength * 2);
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/epoch.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "f3f35O2agtFkbG73RozVRFB", "epoch", undefined);
      var epoch = exports('default', function (date) {
        return Math.floor(date.getTime() / 1000);
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/errors.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _inheritsLoose, _createClass, _assertThisInitialized, _wrapNativeSuper, cclegacy;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _createClass = module.createClass;
      _assertThisInitialized = module.assertThisInitialized;
      _wrapNativeSuper = module.wrapNativeSuper;
    }, function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "21fc5mYaBBIr69Dvz7akrwr", "errors", undefined);
      // import type { KeyLike } from '../types.d'

      /**
       * A generic Error that all other JOSE specific Error subclasses extend.
       *
       * @example
       *
       * Checking thrown error is a JOSE one
       *
       * ```js
       * if (err instanceof jose.errors.JOSEError) {
       *   // ...
       * }
       * ```
       */
      var JOSEError = exports('JOSEError', /*#__PURE__*/function (_Error) {
        _inheritsLoose(JOSEError, _Error);
        /** @ignore */
        function JOSEError(message) {
          var _this;
          _this = _Error.call(this, message) || this;
          /** A unique error code for this particular error subclass. */
          _this.code = 'ERR_JOSE_GENERIC';
          _this.name = _this.constructor.name;
          // @ts-ignore
          Error.captureStackTrace == null || Error.captureStackTrace(_assertThisInitialized(_this), _this.constructor);
          return _this;
        }
        _createClass(JOSEError, null, [{
          key: "code",
          get:
          /**
           * A unique error code for the particular error subclass.
           *
           * @ignore
           */
          function get() {
            return 'ERR_JOSE_GENERIC';
          }
        }]);
        return JOSEError;
      }( /*#__PURE__*/_wrapNativeSuper(Error)));

      /**
       * An error subclass thrown when a JWT Claim Set member validation fails.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWTClaimValidationFailed) {
       *   // ...
       * }
       * ```
       */
      // export class JWTClaimValidationFailed extends JOSEError {
      //   /** @ignore */
      //   static get code(): 'ERR_JWT_CLAIM_VALIDATION_FAILED' {
      //     return 'ERR_JWT_CLAIM_VALIDATION_FAILED'
      //   }

      //   code = 'ERR_JWT_CLAIM_VALIDATION_FAILED'

      //   /** The Claim for which the validation failed. */
      //   claim: string

      //   /** Reason code for the validation failure. */
      //   reason: string

      //   /** @ignore */
      //   constructor(message: string, claim = 'unspecified', reason = 'unspecified') {
      //     super(message)
      //     this.claim = claim
      //     this.reason = reason
      //   }
      // }

      /**
       * An error subclass thrown when a JWT is expired.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWT_EXPIRED') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWTExpired) {
       *   // ...
       * }
       * ```
       */
      // export class JWTExpired extends JOSEError implements JWTClaimValidationFailed {
      //   /** @ignore */
      //   static get code(): 'ERR_JWT_EXPIRED' {
      //     return 'ERR_JWT_EXPIRED'
      //   }

      //   code = 'ERR_JWT_EXPIRED'

      //   /** The Claim for which the validation failed. */
      //   claim: string

      //   /** Reason code for the validation failure. */
      //   reason: string

      //   /** @ignore */
      //   constructor(message: string, claim = 'unspecified', reason = 'unspecified') {
      //     super(message)
      //     this.claim = claim
      //     this.reason = reason
      //   }
      // }

      /**
       * An error subclass thrown when a JOSE Algorithm is not allowed per developer preference.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JOSE_ALG_NOT_ALLOWED') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JOSEAlgNotAllowed) {
       *   // ...
       * }
       * ```
       */
      // export class JOSEAlgNotAllowed extends JOSEError {
      //   /** @ignore */
      //   static get code(): 'ERR_JOSE_ALG_NOT_ALLOWED' {
      //     return 'ERR_JOSE_ALG_NOT_ALLOWED'
      //   }

      //   code = 'ERR_JOSE_ALG_NOT_ALLOWED'
      // }

      /**
       * An error subclass thrown when a particular feature or algorithm is not supported by this
       * implementation or JOSE in general.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JOSE_NOT_SUPPORTED') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JOSENotSupported) {
       *   // ...
       * }
       * ```
       */
      var JOSENotSupported = exports('JOSENotSupported', /*#__PURE__*/function (_JOSEError) {
        _inheritsLoose(JOSENotSupported, _JOSEError);
        function JOSENotSupported() {
          var _this2;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this2 = _JOSEError.call.apply(_JOSEError, [this].concat(args)) || this;
          _this2.code = 'ERR_JOSE_NOT_SUPPORTED';
          return _this2;
        }
        _createClass(JOSENotSupported, null, [{
          key: "code",
          get: /** @ignore */
          function get() {
            return 'ERR_JOSE_NOT_SUPPORTED';
          }
        }]);
        return JOSENotSupported;
      }(JOSEError));

      /**
       * An error subclass thrown when a JWE ciphertext decryption fails.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWE_DECRYPTION_FAILED') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWEDecryptionFailed) {
       *   // ...
       * }
       * ```
       */
      // export class JWEDecryptionFailed extends JOSEError {
      //   /** @ignore */
      //   static get code(): 'ERR_JWE_DECRYPTION_FAILED' {
      //     return 'ERR_JWE_DECRYPTION_FAILED'
      //   }

      //   code = 'ERR_JWE_DECRYPTION_FAILED'

      //   message = 'decryption operation failed'
      // }

      /**
       * An error subclass thrown when a JWE is invalid.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWE_INVALID') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWEInvalid) {
       *   // ...
       * }
       * ```
       */
      var JWEInvalid = exports('JWEInvalid', /*#__PURE__*/function (_JOSEError2) {
        _inheritsLoose(JWEInvalid, _JOSEError2);
        function JWEInvalid() {
          var _this3;
          for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
            args[_key2] = arguments[_key2];
          }
          _this3 = _JOSEError2.call.apply(_JOSEError2, [this].concat(args)) || this;
          _this3.code = 'ERR_JWE_INVALID';
          return _this3;
        }
        _createClass(JWEInvalid, null, [{
          key: "code",
          get: /** @ignore */
          function get() {
            return 'ERR_JWE_INVALID';
          }
        }]);
        return JWEInvalid;
      }(JOSEError));

      /**
       * An error subclass thrown when a JWS is invalid.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWS_INVALID') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWSInvalid) {
       *   // ...
       * }
       * ```
       */
      var JWSInvalid = exports('JWSInvalid', /*#__PURE__*/function (_JOSEError3) {
        _inheritsLoose(JWSInvalid, _JOSEError3);
        function JWSInvalid() {
          var _this4;
          for (var _len3 = arguments.length, args = new Array(_len3), _key3 = 0; _key3 < _len3; _key3++) {
            args[_key3] = arguments[_key3];
          }
          _this4 = _JOSEError3.call.apply(_JOSEError3, [this].concat(args)) || this;
          _this4.code = 'ERR_JWS_INVALID';
          return _this4;
        }
        _createClass(JWSInvalid, null, [{
          key: "code",
          get: /** @ignore */
          function get() {
            return 'ERR_JWS_INVALID';
          }
        }]);
        return JWSInvalid;
      }(JOSEError));

      /**
       * An error subclass thrown when a JWT is invalid.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWT_INVALID') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWTInvalid) {
       *   // ...
       * }
       * ```
       */
      var JWTInvalid = exports('JWTInvalid', /*#__PURE__*/function (_JOSEError4) {
        _inheritsLoose(JWTInvalid, _JOSEError4);
        function JWTInvalid() {
          var _this5;
          for (var _len4 = arguments.length, args = new Array(_len4), _key4 = 0; _key4 < _len4; _key4++) {
            args[_key4] = arguments[_key4];
          }
          _this5 = _JOSEError4.call.apply(_JOSEError4, [this].concat(args)) || this;
          _this5.code = 'ERR_JWT_INVALID';
          return _this5;
        }
        _createClass(JWTInvalid, null, [{
          key: "code",
          get: /** @ignore */
          function get() {
            return 'ERR_JWT_INVALID';
          }
        }]);
        return JWTInvalid;
      }(JOSEError));

      /**
       * An error subclass thrown when a JWK is invalid.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWK_INVALID') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWKInvalid) {
       *   // ...
       * }
       * ```
       */
      // export class JWKInvalid extends JOSEError {
      //   /** @ignore */
      //   static get code(): 'ERR_JWK_INVALID' {
      //     return 'ERR_JWK_INVALID'
      //   }

      //   code = 'ERR_JWK_INVALID'
      // }

      /**
       * An error subclass thrown when a JWKS is invalid.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWKS_INVALID') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWKSInvalid) {
       *   // ...
       * }
       * ```
       */
      // export class JWKSInvalid extends JOSEError {
      //   /** @ignore */
      //   static get code(): 'ERR_JWKS_INVALID' {
      //     return 'ERR_JWKS_INVALID'
      //   }

      //   code = 'ERR_JWKS_INVALID'
      // }

      /**
       * An error subclass thrown when no keys match from a JWKS.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWKS_NO_MATCHING_KEY') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWKSNoMatchingKey) {
       *   // ...
       * }
       * ```
       */
      // export class JWKSNoMatchingKey extends JOSEError {
      //   /** @ignore */
      //   static get code(): 'ERR_JWKS_NO_MATCHING_KEY' {
      //     return 'ERR_JWKS_NO_MATCHING_KEY'
      //   }

      //   code = 'ERR_JWKS_NO_MATCHING_KEY'

      //   message = 'no applicable key found in the JSON Web Key Set'
      // }

      /**
       * An error subclass thrown when multiple keys match from a JWKS.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWKS_MULTIPLE_MATCHING_KEYS') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWKSMultipleMatchingKeys) {
       *   // ...
       * }
       * ```
       */
      // export class JWKSMultipleMatchingKeys extends JOSEError {
      //   /** @ignore */
      //   [Symbol.asyncIterator]!: () => AsyncIterableIterator<KeyLike>

      //   static get code(): 'ERR_JWKS_MULTIPLE_MATCHING_KEYS' {
      //     return 'ERR_JWKS_MULTIPLE_MATCHING_KEYS'
      //   }

      //   code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS'

      //   message = 'multiple matching keys found in the JSON Web Key Set'
      // }

      /**
       * Timeout was reached when retrieving the JWKS response.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWKS_TIMEOUT') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWKSTimeout) {
       *   // ...
       * }
       * ```
       */
      // export class JWKSTimeout extends JOSEError {
      //   /** @ignore */
      //   static get code(): 'ERR_JWKS_TIMEOUT' {
      //     return 'ERR_JWKS_TIMEOUT'
      //   }

      //   code = 'ERR_JWKS_TIMEOUT'

      //   message = 'request timed out'
      // }

      /**
       * An error subclass thrown when JWS signature verification fails.
       *
       * @example
       *
       * Checking thrown error is this one using a stable error code
       *
       * ```js
       * if (err.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
       *   // ...
       * }
       * ```
       *
       * @example
       *
       * Checking thrown error is this one using `instanceof`
       *
       * ```js
       * if (err instanceof jose.errors.JWSSignatureVerificationFailed) {
       *   // ...
       * }
       * ```
       */
      // export class JWSSignatureVerificationFailed extends JOSEError {
      //   /** @ignore */
      //   static get code(): 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' {
      //     return 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'
      //   }

      //   code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'

      //   message = 'signature verification failed'
      // }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/EventMng.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseSingleton.ts'], function (exports) {
  var _inheritsLoose, _createForOfIteratorHelperLoose, cclegacy, _decorator, EventTarget, BaseSingleton;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      EventTarget = module.EventTarget;
    }, function (module) {
      BaseSingleton = module.default;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "ed5f4HEXp1GWa1zxlwWYkep", "EventMng", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var EventMng = exports('default', (_dec = ccclass('EventMng'), _dec(_class = /*#__PURE__*/function (_BaseSingleton) {
        _inheritsLoose(EventMng, _BaseSingleton);
        function EventMng() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseSingleton.call.apply(_BaseSingleton, [this].concat(args)) || this;
          _this.mapEvnet = new Map();
          return _this;
        }
        var _proto = EventMng.prototype;
        _proto.init = function init() {
          var arr = Object.values(NotificationType);
          /**因為會包含KEY文字，所以只取數字index部分 */
          var numArr = arr.filter(function (item) {
            return typeof item === "number";
          });
          //如果value都是文字代表有賦值，陣列內容物正常        
          if (numArr.length != 0) arr = numArr;
          // warn(arr)
          for (var _iterator = _createForOfIteratorHelperLoose(arr), _step; !(_step = _iterator()).done;) {
            var index = _step.value;
            this.mapEvnet.set(index, new EventTarget());
          }
          // warn(this.mapEvnet)
        };

        _proto.emit = function emit(notiType, emitType) {
          var _this$mapEvnet$get;
          for (var _len2 = arguments.length, any = new Array(_len2 > 2 ? _len2 - 2 : 0), _key2 = 2; _key2 < _len2; _key2++) {
            any[_key2 - 2] = arguments[_key2];
          }
          (_this$mapEvnet$get = this.mapEvnet.get(notiType)).emit.apply(_this$mapEvnet$get, [emitType].concat(any));
        };
        _proto.setEvent = function setEvent(notiType, emitType, callback, target) {
          this.mapEvnet.get(notiType).on(emitType, callback, target);
        };
        _proto.deletEvent = function deletEvent(notiType, emitType, callback, target) {
          this.mapEvnet.get(notiType).off(emitType, callback, target);
        };
        return EventMng;
      }(BaseSingleton())) || _class));
      var NotificationType = exports('NotificationType', /*#__PURE__*/function (NotificationType) {
        NotificationType[NotificationType["Basic"] = 0] = "Basic";
        NotificationType[NotificationType["GameAPI"] = 1] = "GameAPI";
        NotificationType[NotificationType["Game"] = 2] = "Game";
        NotificationType[NotificationType["ScrollView"] = 3] = "ScrollView";
        return NotificationType;
      }({}));
      EventMng.getInstance.init();
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/evpkdf.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js', './md5.js'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, Base, MD5Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
      Base = module.Base;
    }, function (module) {
      MD5Algo = module.MD5Algo;
    }],
    execute: function () {
      cclegacy._RF.push({}, "6f5978SW3dFkbcAiSuUTV/o", "evpkdf", undefined);

      /**
       * This key derivation function is meant to conform with EVP_BytesToKey.
       * www.openssl.org/docs/crypto/EVP_BytesToKey.html
       */
      var EvpKDFAlgo = exports('EvpKDFAlgo', /*#__PURE__*/function (_Base) {
        _inheritsLoose(EvpKDFAlgo, _Base);
        /**
         * Initializes a newly created key derivation function.
         *
         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
         *
         * @example
         *
         *     const kdf = CryptoJS.algo.EvpKDF.create();
         *     const kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
         *     const kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
         */
        function EvpKDFAlgo(cfg) {
          var _this;
          _this = _Base.call(this) || this;

          /**
           * Configuration options.
           *
           * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
           * @property {Hasher} hasher The hash algorithm to use. Default: MD5
           * @property {number} iterations The number of iterations to perform. Default: 1
           */
          _this.cfg = Object.assign(new Base(), {
            keySize: 128 / 32,
            hasher: MD5Algo,
            iterations: 1
          }, cfg);
          return _this;
        }

        /**
         * Derives a key from a password.
         *
         * @param {WordArray|string} password The password.
         * @param {WordArray|string} salt A salt.
         *
         * @return {WordArray} The derived key.
         *
         * @example
         *
         *     const key = kdf.compute(password, salt);
         */
        var _proto = EvpKDFAlgo.prototype;
        _proto.compute = function compute(password, salt) {
          var block;

          // Shortcut
          var cfg = this.cfg;

          // Init hasher
          var hasher = cfg.hasher.create();

          // Initial values
          var derivedKey = WordArray.create();

          // Shortcuts
          var derivedKeyWords = derivedKey.words;
          var keySize = cfg.keySize,
            iterations = cfg.iterations;

          // Generate key
          while (derivedKeyWords.length < keySize) {
            if (block) {
              hasher.update(block);
            }
            block = hasher.update(password).finalize(salt);
            hasher.reset();

            // Iterations
            for (var i = 1; i < iterations; i += 1) {
              block = hasher.finalize(block);
              hasher.reset();
            }
            derivedKey.concat(block);
          }
          derivedKey.sigBytes = keySize * 4;
          return derivedKey;
        };
        return EvpKDFAlgo;
      }(Base));

      /**
       * Derives a key from a password.
       *
       * @param {WordArray|string} password The password.
       * @param {WordArray|string} salt A salt.
       * @param {Object} cfg (Optional) The configuration options to use for this computation.
       *
       * @return {WordArray} The derived key.
       *
       * @static
       *
       * @example
       *
       *     var key = CryptoJS.EvpKDF(password, salt);
       *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
       *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
       */
      var EvpKDF = exports('EvpKDF', function EvpKDF(password, salt, cfg) {
        return EvpKDFAlgo.create(cfg).compute(password, salt);
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/format-hex.js", ['cc', './cipher-core.js', './core.js'], function (exports) {
  var cclegacy, CipherParams, Hex;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      CipherParams = module.CipherParams;
    }, function (module) {
      Hex = module.Hex;
    }],
    execute: function () {
      cclegacy._RF.push({}, "e6532eAJlZKQ5ORJ7fdJncB", "format-hex", undefined);
      var HexFormatter = exports('HexFormatter', {
        /**
         * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
         *
         * @param {CipherParams} cipherParams The cipher params object.
         *
         * @return {string} The hexadecimally encoded string.
         *
         * @static
         *
         * @example
         *
         *     var hexString = CryptoJS.format.Hex.stringify(cipherParams);
         */
        stringify: function stringify(cipherParams) {
          return cipherParams.ciphertext.toString(Hex);
        },
        /**
         * Converts a hexadecimally encoded ciphertext string to a cipher params object.
         *
         * @param {string} input The hexadecimally encoded string.
         *
         * @return {CipherParams} The cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var cipherParams = CryptoJS.format.Hex.parse(hexString);
         */
        parse: function parse(input) {
          var ciphertext = Hex.parse(input);
          return CipherParams.create({
            ciphertext: ciphertext
          });
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/GameContorl.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './BaseSingletonComponent.ts', './ScreenAdapter.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _asyncToGenerator, _regeneratorRuntime, cclegacy, _decorator, resources, Prefab, instantiate, director, BaseComponent, BaseSingletonComponent, ScreenAdapter;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      resources = module.resources;
      Prefab = module.Prefab;
      instantiate = module.instantiate;
      director = module.director;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      BaseSingletonComponent = module.default;
    }, function (module) {
      ScreenAdapter = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "1893e3owbtN5LH1cVY73EVW", "GameContorl", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var GameContorl = exports('default', (_dec = ccclass('GameContorl'), _dec2 = property(ScreenAdapter), _dec(_class = (_class2 = /*#__PURE__*/function (_BaseSingletonCompone) {
        _inheritsLoose(GameContorl, _BaseSingletonCompone);
        function GameContorl() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseSingletonCompone.call.apply(_BaseSingletonCompone, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "screenAdapter", _descriptor, _assertThisInitialized(_this));
          _this.isPrefabLoad = void 0;
          _this.base = [];
          return _this;
        }
        var _proto = GameContorl.prototype;
        _proto.onLoad = function onLoad() {
          var _this2 = this;
          _BaseSingletonCompone.prototype.onLoad.call(this);
          resources.loadDir('PanelPrefab', Prefab, function (err, prefabs) {
            console.log("EndLoad", err, prefabs);
            prefabs.forEach(function (_prefab) {
              var _node = instantiate(_prefab);
              _this2.base.push(_node.getComponent(BaseComponent));
            });
            _this2.isPrefabLoad = true;
          });
        };
        _proto.moveBase = function moveBase() {
          this.base.forEach(function (_base) {
            _base.node.setParent(director.getScene());
          });
        };
        _proto.setPanelIndex = /*#__PURE__*/function () {
          var _setPanelIndex = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
            var _this3 = this;
            var index, findIndex;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  if (this.isPrefabLoad) {
                    _context.next = 3;
                    break;
                  }
                  _context.next = 3;
                  return new Promise(function (resolve, reject) {
                    setInterval(function () {
                      if (_this3.isPrefabLoad && _this3.screenAdapter.isInit) resolve();
                    }, 16);
                  });
                case 3:
                  for (index = 0; index < this.base.length; index++) {
                    for (findIndex = 0; findIndex < this.base.length; findIndex++) {
                      if (this.base[findIndex].zIndex == index) {
                        this.base[findIndex].node.setParent(this.screenAdapter.canvas.node);
                        this.base[findIndex].setZIndex();
                      }
                    }
                  }
                case 4:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function setPanelIndex() {
            return _setPanelIndex.apply(this, arguments);
          }
          return setPanelIndex;
        }();
        return GameContorl;
      }(BaseSingletonComponent()), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "screenAdapter", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/get_sign_verify_key.ts", ['cc', './crypto_key.ts', './invalid_key_input.ts', './is_key_like.ts', './webcrypto.ts'], function (exports) {
  var cclegacy, checkSigCryptoKey, invalidKeyInput, types, isCryptoKey;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      checkSigCryptoKey = module.checkSigCryptoKey;
    }, function (module) {
      invalidKeyInput = module.default;
    }, function (module) {
      types = module.types;
    }, function (module) {
      isCryptoKey = module.isCryptoKey;
    }],
    execute: function () {
      exports('default', getCryptoKey);
      cclegacy._RF.push({}, "b99b79YLetC0LN3Fc9WdINm", "get_sign_verify_key", undefined);
      function getCryptoKey(alg, key, usage) {
        if (isCryptoKey(key)) {
          checkSigCryptoKey(key, alg, usage);
          return key;
        }
        if (key instanceof Uint8Array) {
          if (!alg.startsWith('HS')) {
            throw new TypeError(invalidKeyInput.apply(void 0, [key].concat(types)));
          }
          console.warn(crypto);
          return crypto.subtle.importKey('raw', key, {
            hash: "SHA-" + alg.slice(-3),
            name: 'HMAC'
          }, false, [usage]);
        }
        throw new TypeError(invalidKeyInput.apply(void 0, [key].concat(types, ['Uint8Array'])));
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/GoogleSheet.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './index2.ts', './SheetData.ts', './sign2.ts', './import.ts'], function (exports) {
  var _asyncToGenerator, _regeneratorRuntime, cclegacy, warn, SheetData, SignJWT, importPKCS8;
  return {
    setters: [function (module) {
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
      warn = module.warn;
    }, null, function (module) {
      SheetData = module.default;
    }, function (module) {
      SignJWT = module.SignJWT;
    }, function (module) {
      importPKCS8 = module.importPKCS8;
    }],
    execute: function () {
      cclegacy._RF.push({}, "74bbbY5OBdMsJoCQlmCUvNA", "GoogleSheet", undefined);
      /**
       * 
       */
      var GoogleSheet = exports('GoogleSheet', /*#__PURE__*/function () {
        function GoogleSheet() {
          /**
          * 要獲取資料的GoogleSheetID，GoogleSheet的url會像:
          * https://docs.google.com/spreadsheets/d/1xDYmB0PqT0zb6lG6iStnE0bLN-oXOGmlYRrsjfiad0Y/edit#gid=0
          * 其中1xDYmB0PqT0zb6lG6iStnE0bLN-oXOGmlYRrsjfiad0Y就是SheetID
          */
          // private spreadsheetId: string = "1xDYmB0PqT0zb6lG6iStnE0bLN-oXOGmlYRrsjfiad0Y";
          this.spreadsheetId = "";
          this.accessToken = "";
          this.client_email = "";
          this.private_key = "";
          this.token_uri = "";
          this.scope = "https://www.googleapis.com/auth/spreadsheets";
          //服務帳戶有權限的API金鑰
          // private sheetAPIKey = `AIzaSyCwn_uUC0x2z0gSX44Rhycm1LiMd3AS7DU`
          this.sheetAPIKey = "";
          this.sheetURL = "https://sheets.googleapis.com/v4/spreadsheets/";
          //Sheet分頁的名稱
          this.sheetTag = ["\u5DE5\u4F5C\u88681"];
          this.sheetData = new SheetData();
        }
        var _proto = GoogleSheet.prototype;
        _proto.setInfo = function setInfo(JsonKey) {
          var info = JsonKey;
          warn("\u78BA\u8A8D\u91D1\u9470\u50B3\u5165:", info);
          this.client_email = info.client_email;
          this.private_key = info.private_key;
          this.token_uri = info.token_uri;
          return this;
        };
        _proto.getData = /*#__PURE__*/function () {
          var _getData = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(range) {
            var _this = this;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  if (range === void 0) {
                    range = "";
                  }
                  _context.next = 3;
                  return this.getAccessToken();
                case 3:
                  _context.next = 5;
                  return fetch("" + this.sheetURL + this.spreadsheetId + "/values/" + this.sheetTag[0] + range + "?key=" + this.sheetAPIKey, {
                    method: 'GET',
                    headers: {
                      'Authorization': "Bearer " + this.accessToken,
                      'Content-Type': 'application/json'
                    }
                  }).then(function (response) {
                    return response.json();
                  })["catch"](function () {
                    console.error("Failed to fetch access token");
                    _this.sheetData.setDefault();
                  }).then(function (response) {
                    warn(response["values"]);
                    _this.sheetData.setData(response["values"]);
                  });
                case 5:
                  warn("Data OK");
                case 6:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function getData(_x) {
            return _getData.apply(this, arguments);
          }
          return getData;
        }() //------------------------------------------用服務帳戶---------------------------------------
        ;

        _proto.getAccessToken = /*#__PURE__*/
        function () {
          var _getAccessToken = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee2() {
            var _this2 = this;
            var jwt, params, tokenRequest;
            return _regeneratorRuntime().wrap(function _callee2$(_context2) {
              while (1) switch (_context2.prev = _context2.next) {
                case 0:
                  _context2.next = 2;
                  return this.generateJWT();
                case 2:
                  jwt = _context2.sent;
                  params = new URLSearchParams();
                  params.append('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
                  params.append('assertion', jwt);
                  // warn(jwt)
                  tokenRequest = {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: params.toString()
                  };
                  _context2.next = 9;
                  return fetch(this.token_uri, tokenRequest).then(function (response) {
                    return response.json();
                  })["catch"](function (err) {
                    throw new Error("Failed to get ID token: " + err);
                  }).then(function (response) {
                    return _this2.accessToken = response.access_token;
                  });
                case 9:
                  warn("AccessToken OK");
                case 10:
                case "end":
                  return _context2.stop();
              }
            }, _callee2, this);
          }));
          function getAccessToken() {
            return _getAccessToken.apply(this, arguments);
          }
          return getAccessToken;
        }();
        _proto.generateJWT = /*#__PURE__*/function () {
          var _generateJWT = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee3() {
            var now, exp, header, payload, private_key, jwt;
            return _regeneratorRuntime().wrap(function _callee3$(_context3) {
              while (1) switch (_context3.prev = _context3.next) {
                case 0:
                  now = Math.floor(Date.now() / 1000);
                  exp = now + 3600; // 构建 header
                  header = {
                    alg: 'RS256',
                    typ: 'JWT'
                  };
                  payload = {
                    iss: this.client_email,
                    scope: this.scope,
                    aud: this.token_uri,
                    exp: exp,
                    iat: now
                  };
                  _context3.next = 6;
                  return importPKCS8(this.private_key, "RS256");
                case 6:
                  private_key = _context3.sent;
                  jwt = new SignJWT(payload).setProtectedHeader(header).sign(private_key);
                  warn("JWT OK");
                  return _context3.abrupt("return", jwt);
                case 10:
                case "end":
                  return _context3.stop();
              }
            }, _callee3, this);
          }));
          function generateJWT() {
            return _generateJWT.apply(this, arguments);
          }
          return generateJWT;
        }();
        return GoogleSheet;
      }());
      var JsonKey = exports('JsonKey', function JsonKey() {
        this.client_email = "";
        this.private_key = "";
        this.token_uri = "";
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/hmac.js", ['cc', './core.js'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      exports('HMAC', module.HMAC);
    }],
    execute: function () {
      cclegacy._RF.push({}, "1d83fkOOBtL7IeQoA66TPgM", "hmac", undefined);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/IBaseSingleton.ts", ['cc'], function () {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "82b5f6lTeRFZrPk8+C/zvfL", "IBaseSingleton", undefined);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/import.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './asn1.ts'], function (exports) {
  var _asyncToGenerator, _regeneratorRuntime, cclegacy, fromPKCS8;
  return {
    setters: [function (module) {
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      fromPKCS8 = module.fromPKCS8;
    }],
    execute: function () {
      exports('importPKCS8', importPKCS8);
      cclegacy._RF.push({}, "a8e3aI7F2ZErKPlPVnsSzw8", "import", undefined);
      // import asKeyObject from '../runtime/jwk_to_key'

      // import { JOSENotSupported } from '../util/errors'
      // import isObject from '../lib/is_object'
      // import type { JWK, KeyLike } from '../types.d'
      /**
       * Imports a PEM-encoded SPKI string as a runtime-specific public key representation (KeyObject or
       * CryptoKey).
       *
       * Note: The OID id-RSASSA-PSS (1.2.840.113549.1.1.10) is not supported in
       * {@link https://w3c.github.io/webcrypto/ Web Cryptography API}, use the OID rsaEncryption
       * (1.2.840.113549.1.1.1) instead for all RSA algorithms.
       *
       * @example
       *
       * ```js
       * const algorithm = 'ES256'
       * const spki = `-----BEGIN PUBLIC KEY-----
       * MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFlHHWfLk0gLBbsLTcuCrbCqoHqmM
       * YJepMC+Q+Dd6RBmBiA41evUsNMwLeN+PNFqib+xwi9JkJ8qhZkq8Y/IzGg==
       * -----END PUBLIC KEY-----`
       * const ecPublicKey = await jose.importSPKI(spki, algorithm)
       * ```
       *
       * @param spki PEM-encoded SPKI string
       * @param alg (Only effective in Web Crypto API runtimes) JSON Web Algorithm identifier to be used
       *   with the imported key, its presence is only enforced in Web Crypto API runtimes. See
       *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
       */
      // export async function importSPKI<KeyLikeType extends KeyLike = KeyLike>(
      //   spki: string,
      //   alg: string,
      //   options?: PEMImportOptions,
      // ): Promise<KeyLikeType> {
      //   if (typeof spki !== 'string' || spki.indexOf('-----BEGIN PUBLIC KEY-----') !== 0) {
      //     throw new TypeError('"spki" must be SPKI formatted string')
      //   }
      //   // @ts-ignore
      //   return fromSPKI(spki, alg, options)
      // }

      /**
       * Imports the SPKI from an X.509 string certificate as a runtime-specific public key representation
       * (KeyObject or CryptoKey).
       *
       * Note: The OID id-RSASSA-PSS (1.2.840.113549.1.1.10) is not supported in
       * {@link https://w3c.github.io/webcrypto/ Web Cryptography API}, use the OID rsaEncryption
       * (1.2.840.113549.1.1.1) instead for all RSA algorithms.
       *
       * @example
       *
       * ```js
       * const algorithm = 'ES256'
       * const x509 = `-----BEGIN CERTIFICATE-----
       * MIIBXjCCAQSgAwIBAgIGAXvykuMKMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMK3Np
       * QXBNOXpBdk1VaXhXVWVGaGtjZXg1NjJRRzFyQUhXaV96UlFQTVpQaG8wHhcNMjEw
       * OTE3MDcwNTE3WhcNMjIwNzE0MDcwNTE3WjA2MTQwMgYDVQQDDCtzaUFwTTl6QXZN
       * VWl4V1VlRmhrY2V4NTYyUUcxckFIV2lfelJRUE1aUGhvMFkwEwYHKoZIzj0CAQYI
       * KoZIzj0DAQcDQgAE8PbPvCv5D5xBFHEZlBp/q5OEUymq7RIgWIi7tkl9aGSpYE35
       * UH+kBKDnphJO3odpPZ5gvgKs2nwRWcrDnUjYLDAKBggqhkjOPQQDAgNIADBFAiEA
       * 1yyMTRe66MhEXID9+uVub7woMkNYd0LhSHwKSPMUUTkCIFQGsfm1ecXOpeGOufAh
       * v+A1QWZMuTWqYt+uh/YSRNDn
       * -----END CERTIFICATE-----`
       * const ecPublicKey = await jose.importX509(x509, algorithm)
       * ```
       *
       * @param x509 X.509 certificate string
       * @param alg (Only effective in Web Crypto API runtimes) JSON Web Algorithm identifier to be used
       *   with the imported key, its presence is only enforced in Web Crypto API runtimes. See
       *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
       */
      // export async function importX509<KeyLikeType extends KeyLike = KeyLike>(
      //   x509: string,
      //   alg: string,
      //   options?: PEMImportOptions,
      // ): Promise<KeyLikeType> {
      //   if (typeof x509 !== 'string' || x509.indexOf('-----BEGIN CERTIFICATE-----') !== 0) {
      //     throw new TypeError('"x509" must be X.509 formatted string')
      //   }
      //   // @ts-ignore
      //   return fromX509(x509, alg, options)
      // }
      /**
       * Imports a PEM-encoded PKCS#8 string as a runtime-specific private key representation (KeyObject
       * or CryptoKey).
       *
       * Note: The OID id-RSASSA-PSS (1.2.840.113549.1.1.10) is not supported in
       * {@link https://w3c.github.io/webcrypto/ Web Cryptography API}, use the OID rsaEncryption
       * (1.2.840.113549.1.1.1) instead for all RSA algorithms.
       *
       * @example
       *
       * ```js
       * const algorithm = 'ES256'
       * const pkcs8 = `-----BEGIN PRIVATE KEY-----
       * MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiyvo0X+VQ0yIrOaN
       * nlrnUclopnvuuMfoc8HHly3505OhRANCAAQWUcdZ8uTSAsFuwtNy4KtsKqgeqYxg
       * l6kwL5D4N3pEGYGIDjV69Sw0zAt43480WqJv7HCL0mQnyqFmSrxj8jMa
       * -----END PRIVATE KEY-----`
       * const ecPrivateKey = await jose.importPKCS8(pkcs8, algorithm)
       * ```
       *
       * @param pkcs8 PEM-encoded PKCS#8 string
       * @param alg (Only effective in Web Crypto API runtimes) JSON Web Algorithm identifier to be used
       *   with the imported key, its presence is only enforced in Web Crypto API runtimes. See
       *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
       */
      function importPKCS8(_x, _x2, _x3) {
        return _importPKCS.apply(this, arguments);
      }

      /**
       * Imports a JWK to a runtime-specific key representation (KeyLike). Either the JWK "alg"
       * (Algorithm) Parameter, or the optional "alg" argument, must be present.
       *
       * Note: When the runtime is using {@link https://w3c.github.io/webcrypto/ Web Cryptography API} the
       * jwk parameters "use", "key_ops", and "ext" are also used in the resulting `CryptoKey`.
       *
       * @example
       *
       * ```js
       * const ecPublicKey = await jose.importJWK(
       *   {
       *     crv: 'P-256',
       *     kty: 'EC',
       *     x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
       *     y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo',
       *   },
       *   'ES256',
       * )
       *
       * const rsaPublicKey = await jose.importJWK(
       *   {
       *     kty: 'RSA',
       *     e: 'AQAB',
       *     n: '12oBZRhCiZFJLcPg59LkZZ9mdhSMTKAQZYq32k_ti5SBB6jerkh-WzOMAO664r_qyLkqHUSp3u5SbXtseZEpN3XPWGKSxjsy-1JyEFTdLSYe6f9gfrmxkUF_7DTpq0gn6rntP05g2-wFW50YO7mosfdslfrTJYWHFhJALabAeYirYD7-9kqq9ebfFMF4sRRELbv9oi36As6Q9B3Qb5_C1rAzqfao_PCsf9EPsTZsVVVkA5qoIAr47lo1ipfiBPxUCCNSdvkmDTYgvvRm6ZoMjFbvOtgyts55fXKdMWv7I9HMD5HwE9uW839PWA514qhbcIsXEYSFMPMV6fnlsiZvQQ',
       *   },
       *   'PS256',
       * )
       * ```
       *
       * @param jwk JSON Web Key.
       * @param alg (Only effective in Web Crypto API runtimes) JSON Web Algorithm identifier to be used
       *   with the imported key. Default is the "alg" property on the JWK, its presence is only enforced
       *   in Web Crypto API runtimes. See
       *   {@link https://github.com/panva/jose/issues/210 Algorithm Key Requirements}.
       */
      // export async function importJWK<KeyLikeType extends KeyLike = KeyLike>(
      //   jwk: JWK,
      //   alg?: string,
      // ): Promise<KeyLikeType | Uint8Array> {
      //   if (!isObject(jwk)) {
      //     throw new TypeError('JWK must be an object')
      //   }

      //   alg ||= jwk.alg

      //   switch (jwk.kty) {
      //     case 'oct':
      //       if (typeof jwk.k !== 'string' || !jwk.k) {
      //         throw new TypeError('missing "k" (Key Value) Parameter value')
      //       }

      //       return decodeBase64URL(jwk.k)
      //     case 'RSA':
      //       if (jwk.oth !== undefined) {
      //         throw new JOSENotSupported(
      //           'RSA JWK "oth" (Other Primes Info) Parameter value is not supported',
      //         )
      //       }
      //     case 'EC':
      //     case 'OKP':
      //       // @ts-ignore
      //       return asKeyObject({ ...jwk, alg })
      //     default:
      //       throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value')
      //   }
      // }
      function _importPKCS() {
        _importPKCS = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(pkcs8, alg, options) {
          return _regeneratorRuntime().wrap(function _callee$(_context) {
            while (1) switch (_context.prev = _context.next) {
              case 0:
                if (!(typeof pkcs8 !== 'string' || pkcs8.indexOf('-----BEGIN PRIVATE KEY-----') !== 0)) {
                  _context.next = 2;
                  break;
                }
                throw new TypeError('"pkcs8" must be PKCS#8 formatted string');
              case 2:
                return _context.abrupt("return", fromPKCS8(pkcs8, alg, options));
              case 3:
              case "end":
                return _context.stop();
            }
          }, _callee);
        }));
        return _importPKCS.apply(this, arguments);
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/index.js", ['cc', './core.js', './x64-core.js', './cipher-core.js', './enc-utf16.js', './enc-base64.js', './enc-base64url.js', './hmac.js', './md5.js', './sha1.js', './sha224.js', './sha256.js', './sha384.js', './sha512.js', './sha3.js', './ripemd160.js', './pbkdf2.js', './evpkdf.js', './aes.js', './tripledes.js', './rabbit.js', './rabbit-legacy.js', './rc4.js', './blowfish.js', './mode-cfb.js', './mode-ctr.js', './mode-ctr-gladman.js', './mode-ecb.js', './mode-ofb.js', './pad-ansix923.js', './pad-iso10126.js', './pad-iso97971.js', './pad-nopadding.js', './pad-zeropadding.js', './format-hex.js'], function (exports) {
  var cclegacy, Base, WordArray, BufferedBlockAlgorithm, Hasher, Hex, Latin1, Utf8, HMAC, X64Word, X64WordArray, Cipher, StreamCipher, BlockCipherMode, BlockCipher, CipherParams, SerializableCipher, PasswordBasedCipher, CBC, Pkcs7, OpenSSLFormatter, OpenSSLKdf, Utf16, Utf16BE, Utf16LE, Base64, Base64url, MD5Algo, MD5, HmacMD5, SHA1Algo, SHA1, HmacSHA1, SHA224Algo, SHA224, HmacSHA224, SHA256Algo, SHA256, HmacSHA256, SHA384Algo, SHA384, HmacSHA384, SHA512Algo, SHA512, HmacSHA512, SHA3Algo, SHA3, HmacSHA3, RIPEMD160Algo, RIPEMD160, HmacRIPEMD160, PBKDF2Algo, PBKDF2, EvpKDFAlgo, EvpKDF, AESAlgo, AES, DESAlgo, TripleDESAlgo, DES, TripleDES, RabbitAlgo, Rabbit, RabbitLegacyAlgo, RabbitLegacy, RC4Algo, RC4DropAlgo, RC4, RC4Drop, BlowfishAlgo, Blowfish, CFB, CTR, CTRGladman, ECB, OFB, AnsiX923, Iso10126, Iso97971, NoPadding, ZeroPadding, HexFormatter;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      Base = module.Base;
      WordArray = module.WordArray;
      BufferedBlockAlgorithm = module.BufferedBlockAlgorithm;
      Hasher = module.Hasher;
      Hex = module.Hex;
      Latin1 = module.Latin1;
      Utf8 = module.Utf8;
      HMAC = module.HMAC;
    }, function (module) {
      X64Word = module.X64Word;
      X64WordArray = module.X64WordArray;
    }, function (module) {
      Cipher = module.Cipher;
      StreamCipher = module.StreamCipher;
      BlockCipherMode = module.BlockCipherMode;
      BlockCipher = module.BlockCipher;
      CipherParams = module.CipherParams;
      SerializableCipher = module.SerializableCipher;
      PasswordBasedCipher = module.PasswordBasedCipher;
      CBC = module.CBC;
      Pkcs7 = module.Pkcs7;
      OpenSSLFormatter = module.OpenSSLFormatter;
      OpenSSLKdf = module.OpenSSLKdf;
    }, function (module) {
      Utf16 = module.Utf16;
      Utf16BE = module.Utf16BE;
      Utf16LE = module.Utf16LE;
    }, function (module) {
      Base64 = module.Base64;
    }, function (module) {
      Base64url = module.Base64url;
    }, null, function (module) {
      MD5Algo = module.MD5Algo;
      MD5 = module.MD5;
      HmacMD5 = module.HmacMD5;
    }, function (module) {
      SHA1Algo = module.SHA1Algo;
      SHA1 = module.SHA1;
      HmacSHA1 = module.HmacSHA1;
    }, function (module) {
      SHA224Algo = module.SHA224Algo;
      SHA224 = module.SHA224;
      HmacSHA224 = module.HmacSHA224;
    }, function (module) {
      SHA256Algo = module.SHA256Algo;
      SHA256 = module.SHA256;
      HmacSHA256 = module.HmacSHA256;
    }, function (module) {
      SHA384Algo = module.SHA384Algo;
      SHA384 = module.SHA384;
      HmacSHA384 = module.HmacSHA384;
    }, function (module) {
      SHA512Algo = module.SHA512Algo;
      SHA512 = module.SHA512;
      HmacSHA512 = module.HmacSHA512;
    }, function (module) {
      SHA3Algo = module.SHA3Algo;
      SHA3 = module.SHA3;
      HmacSHA3 = module.HmacSHA3;
    }, function (module) {
      RIPEMD160Algo = module.RIPEMD160Algo;
      RIPEMD160 = module.RIPEMD160;
      HmacRIPEMD160 = module.HmacRIPEMD160;
    }, function (module) {
      PBKDF2Algo = module.PBKDF2Algo;
      PBKDF2 = module.PBKDF2;
    }, function (module) {
      EvpKDFAlgo = module.EvpKDFAlgo;
      EvpKDF = module.EvpKDF;
    }, function (module) {
      AESAlgo = module.AESAlgo;
      AES = module.AES;
    }, function (module) {
      DESAlgo = module.DESAlgo;
      TripleDESAlgo = module.TripleDESAlgo;
      DES = module.DES;
      TripleDES = module.TripleDES;
    }, function (module) {
      RabbitAlgo = module.RabbitAlgo;
      Rabbit = module.Rabbit;
    }, function (module) {
      RabbitLegacyAlgo = module.RabbitLegacyAlgo;
      RabbitLegacy = module.RabbitLegacy;
    }, function (module) {
      RC4Algo = module.RC4Algo;
      RC4DropAlgo = module.RC4DropAlgo;
      RC4 = module.RC4;
      RC4Drop = module.RC4Drop;
    }, function (module) {
      BlowfishAlgo = module.BlowfishAlgo;
      Blowfish = module.Blowfish;
    }, function (module) {
      CFB = module.CFB;
    }, function (module) {
      CTR = module.CTR;
    }, function (module) {
      CTRGladman = module.CTRGladman;
    }, function (module) {
      ECB = module.ECB;
    }, function (module) {
      OFB = module.OFB;
    }, function (module) {
      AnsiX923 = module.AnsiX923;
    }, function (module) {
      Iso10126 = module.Iso10126;
    }, function (module) {
      Iso97971 = module.Iso97971;
    }, function (module) {
      NoPadding = module.NoPadding;
    }, function (module) {
      ZeroPadding = module.ZeroPadding;
    }, function (module) {
      HexFormatter = module.HexFormatter;
    }],
    execute: function () {
      cclegacy._RF.push({}, "6b537Q13bRFeJwsWwL5SAsr", "index", undefined);
      var index = exports('default', {
        lib: {
          Base: Base,
          WordArray: WordArray,
          BufferedBlockAlgorithm: BufferedBlockAlgorithm,
          Hasher: Hasher,
          Cipher: Cipher,
          StreamCipher: StreamCipher,
          BlockCipherMode: BlockCipherMode,
          BlockCipher: BlockCipher,
          CipherParams: CipherParams,
          SerializableCipher: SerializableCipher,
          PasswordBasedCipher: PasswordBasedCipher
        },
        x64: {
          Word: X64Word,
          WordArray: X64WordArray
        },
        enc: {
          Hex: Hex,
          Latin1: Latin1,
          Utf8: Utf8,
          Utf16: Utf16,
          Utf16BE: Utf16BE,
          Utf16LE: Utf16LE,
          Base64: Base64,
          Base64url: Base64url
        },
        algo: {
          HMAC: HMAC,
          MD5: MD5Algo,
          SHA1: SHA1Algo,
          SHA224: SHA224Algo,
          SHA256: SHA256Algo,
          SHA384: SHA384Algo,
          SHA512: SHA512Algo,
          SHA3: SHA3Algo,
          RIPEMD160: RIPEMD160Algo,
          PBKDF2: PBKDF2Algo,
          EvpKDF: EvpKDFAlgo,
          AES: AESAlgo,
          DES: DESAlgo,
          TripleDES: TripleDESAlgo,
          Rabbit: RabbitAlgo,
          RabbitLegacy: RabbitLegacyAlgo,
          RC4: RC4Algo,
          RC4Drop: RC4DropAlgo,
          Blowfish: BlowfishAlgo
        },
        mode: {
          CBC: CBC,
          CFB: CFB,
          CTR: CTR,
          CTRGladman: CTRGladman,
          ECB: ECB,
          OFB: OFB
        },
        pad: {
          Pkcs7: Pkcs7,
          AnsiX923: AnsiX923,
          Iso10126: Iso10126,
          Iso97971: Iso97971,
          NoPadding: NoPadding,
          ZeroPadding: ZeroPadding
        },
        format: {
          OpenSSL: OpenSSLFormatter,
          Hex: HexFormatter
        },
        kdf: {
          OpenSSL: OpenSSLKdf
        },
        MD5: MD5,
        HmacMD5: HmacMD5,
        SHA1: SHA1,
        HmacSHA1: HmacSHA1,
        SHA224: SHA224,
        HmacSHA224: HmacSHA224,
        SHA256: SHA256,
        HmacSHA256: HmacSHA256,
        SHA384: SHA384,
        HmacSHA384: HmacSHA384,
        SHA512: SHA512,
        HmacSHA512: HmacSHA512,
        SHA3: SHA3,
        HmacSHA3: HmacSHA3,
        RIPEMD160: RIPEMD160,
        HmacRIPEMD160: HmacRIPEMD160,
        PBKDF2: PBKDF2,
        EvpKDF: EvpKDF,
        AES: AES,
        DES: DES,
        TripleDES: TripleDES,
        Rabbit: Rabbit,
        RabbitLegacy: RabbitLegacy,
        RC4: RC4,
        RC4Drop: RC4Drop,
        Blowfish: Blowfish
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/index.ts", ['cc', './browser_client.ts', './mod2.ts', './mod.ts'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      exports('Client', module.Client);
    }, null, function (module) {
      exports('decode', module.decode);
    }],
    execute: function () {
      cclegacy._RF.push({}, "71db33+gLJGn6Lzty32BNQc", "index", undefined);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/index2.ts", ['cc', './sign2.ts', './import.ts'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      exports('SignJWT', module.SignJWT);
    }, function (module) {
      exports('importPKCS8', module.importPKCS8);
    }],
    execute: function () {
      cclegacy._RF.push({}, "7e322ek18lJqLbDvCwRNVY+", "index", undefined);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/invalid_key_input.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports('withAlg', withAlg);
      cclegacy._RF.push({}, "b49fd04zMtM9Lxt1reqLnrj", "invalid_key_input", undefined);
      function message(msg, actual) {
        for (var _len = arguments.length, types = new Array(_len > 2 ? _len - 2 : 0), _key = 2; _key < _len; _key++) {
          types[_key - 2] = arguments[_key];
        }
        if (types.length > 2) {
          var last = types.pop();
          msg += "one of type " + types.join(', ') + ", or " + last + ".";
        } else if (types.length === 2) {
          msg += "one of type " + types[0] + " or " + types[1] + ".";
        } else {
          msg += "of type " + types[0] + ".";
        }
        if (actual == null) {
          msg += " Received " + actual;
        } else if (typeof actual === 'function' && actual.name) {
          msg += " Received function " + actual.name;
        } else if (typeof actual === 'object' && actual != null) {
          var _actual$constructor;
          if ((_actual$constructor = actual.constructor) != null && _actual$constructor.name) {
            msg += " Received an instance of " + actual.constructor.name;
          }
        }
        return msg;
      }
      var invalidKeyInput = exports('default', function (actual) {
        for (var _len2 = arguments.length, types = new Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
          types[_key2 - 1] = arguments[_key2];
        }
        return message.apply(void 0, ['Key must be ', actual].concat(types));
      });
      function withAlg(alg, actual) {
        for (var _len3 = arguments.length, types = new Array(_len3 > 2 ? _len3 - 2 : 0), _key3 = 2; _key3 < _len3; _key3++) {
          types[_key3 - 2] = arguments[_key3];
        }
        return message.apply(void 0, ["Key for the " + alg + " algorithm must be ", actual].concat(types));
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/is_disjoint.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _createForOfIteratorHelperLoose, cclegacy;
  return {
    setters: [function (module) {
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "7b870kuOp5OnaUnHuVTxOGF", "is_disjoint", undefined);
      var isDisjoint = exports('default', function isDisjoint() {
        for (var _len = arguments.length, headers = new Array(_len), _key = 0; _key < _len; _key++) {
          headers[_key] = arguments[_key];
        }
        var sources = headers.filter(Boolean);
        if (sources.length === 0 || sources.length === 1) {
          return true;
        }
        var acc;
        for (var _iterator = _createForOfIteratorHelperLoose(sources), _step; !(_step = _iterator()).done;) {
          var header = _step.value;
          var parameters = Object.keys(header);
          if (!acc || acc.size === 0) {
            acc = new Set(parameters);
            continue;
          }
          for (var _i = 0, _parameters = parameters; _i < _parameters.length; _i++) {
            var parameter = _parameters[_i];
            if (acc.has(parameter)) {
              return false;
            }
            acc.add(parameter);
          }
        }
        return true;
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/is_key_like.ts", ['cc', './webcrypto.ts'], function (exports) {
  var cclegacy, isCryptoKey;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      isCryptoKey = module.isCryptoKey;
    }],
    execute: function () {
      cclegacy._RF.push({}, "9d62fLG57NFCK/dMoZ9YXNf", "is_key_like", undefined);
      var isKeyLike = exports('default', function (key) {
        return isCryptoKey(key);
      });
      var types = exports('types', ['CryptoKey']);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/is_object.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports('default', isObject);
      cclegacy._RF.push({}, "2e06cx7klZPDJlRpIvz8VAV", "is_object", undefined);
      function isObjectLike(value) {
        return typeof value === 'object' && value !== null;
      }
      function isObject(input) {
        if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
          return false;
        }
        if (Object.getPrototypeOf(input) === null) {
          return true;
        }
        var proto = input;
        while (Object.getPrototypeOf(proto) !== null) {
          proto = Object.getPrototypeOf(proto);
        }
        return Object.getPrototypeOf(input) === proto;
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/LabelButton.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Label, warn, Color, Button;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Label = module.Label;
      warn = module.warn;
      Color = module.Color;
      Button = module.Button;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "91cbeL4NbpOD4eCRR+lL3SS", "LabelButton", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var State = /*#__PURE__*/function (State) {
        State[State["NORMAL"] = 0] = "NORMAL";
        State[State["HOVER"] = 1] = "HOVER";
        State[State["PRESSED"] = 2] = "PRESSED";
        State[State["DISABLED"] = 3] = "DISABLED";
        return State;
      }(State || {});
      var LabelButton = exports('default', (_dec = ccclass('LabelButton'), _dec2 = property({
        type: Label,
        tooltip: "target有時候都會綁自身Buttton，自身掛載Sprtie， 所以Label要另外做"
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_Button) {
        _inheritsLoose(LabelButton, _Button);
        function LabelButton() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Button.call.apply(_Button, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "label", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = LabelButton.prototype;
        /**多載解決編譯問題 */
        _proto._updateColorTransition = function _updateColorTransition(state) {
          _Button.prototype._updateColorTransition.call(this, state);
          if (this.label) this.label.color = this._getColorByState(state);
        };
        _proto._getColorByState = function _getColorByState(state) {
          switch (state) {
            case State.NORMAL:
              return this._normalColor;
            case State.DISABLED:
              return this._disabledColor;
            case State.HOVER:
              return this._hoverColor;
            case State.PRESSED:
              return this._pressedColor;
            default:
              // Should not arrive here.
              {
                warn('Button._getColorByState(): wrong state.');
              }
              return new Color();
          }
        };
        return LabelButton;
      }(Button), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "label", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/LanguageManager.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseSingleton.ts', './Public.ts'], function (exports) {
  var _inheritsLoose, _asyncToGenerator, _regeneratorRuntime, cclegacy, resources, JsonAsset, sys, BaseSingleton, Plug;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
      resources = module.resources;
      JsonAsset = module.JsonAsset;
      sys = module.sys;
    }, function (module) {
      BaseSingleton = module.default;
    }, function (module) {
      Plug = module.Plug;
    }],
    execute: function () {
      cclegacy._RF.push({}, "3b42aAon6lGYozr1kVVTJbt", "LanguageManager", undefined);
      var LanguageManager = exports('default', /*#__PURE__*/function (_BaseSingleton) {
        _inheritsLoose(LanguageManager, _BaseSingleton);
        function LanguageManager() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseSingleton.call.apply(_BaseSingleton, [this].concat(args)) || this;
          _this.Language = "";
          _this.gameData = new Object();
          _this.serverData = new Object();
          _this.serverAPIData = new Object();
          _this.isGame = void 0;
          _this.isServer = void 0;
          _this.isServerAPI = void 0;
          _this.loadCount = void 0;
          return _this;
        }
        var _proto = LanguageManager.prototype;
        /**遊戲內切換語系時，可以帶入參數切換，否則會走預設判斷 */
        _proto.startLoad = function startLoad(gameID, lang) {
          if (!lang) lang = this.getLanguage();
          if (lang === this.Language) return;
          this.Language = lang;
          var lib = this.checkLanguagePath();
          /**再研究一下html端與app端為什麼兩天會有點不一樣，lib路徑設定?? */
          this.switchLoad(lib + "/gameLanguage/" + gameID.toString() + "/" + lang);
          this.switchLoad(lib + "/serverLanguage/" + lang);
          this.switchLoad(lib + "/serverApiLanguage/" + lang);
        };
        _proto.setDate = function setDate(_data, _type) {
          console.log(_type, _data);
          var data = this.getTypeData(_type);
          // console.log(data);
          for (var key in _data) {
            if (!Object.prototype.hasOwnProperty.call(data, key)) {
              data[key] = _data[key];
            }
          }
          switch (_type) {
            case LangType.Game:
              this.isGame = true;
            case LangType.Server:
              this.isServer = true;
            case LangType.ServerAPI:
              this.isServerAPI = true;
          }
          return this;
          //@ts-ignore
          // this.data = data;
          // console.log(language);
        };

        _proto.t = function t(option, _type) {
          var data = this.getTypeData(_type);
          // console.log(option);
          // console.log(data);
          if (data == null) {
            return option;
          }
          return data[option] == null ? option : data[option];
        };
        _proto.checkSetLang = /*#__PURE__*/function () {
          var _checkSetLang = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
            var _this2 = this;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  return _context.abrupt("return", new Promise(function (resolve, reject) {
                    if (_this2.Language != "") resolve();
                    var checkLoop = setInterval(function () {
                      var isbool = _this2.Language == "" ? true : false;
                      if (!isbool) {
                        resolve();
                        clearInterval(checkLoop);
                      }
                    }, 100);
                  }));
                case 1:
                case "end":
                  return _context.stop();
              }
            }, _callee);
          }));
          function checkSetLang() {
            return _checkSetLang.apply(this, arguments);
          }
          return checkSetLang;
        }();
        _proto.checkLanguage = /*#__PURE__*/function () {
          var _checkLanguage = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee2(_type) {
            var _this3 = this;
            return _regeneratorRuntime().wrap(function _callee2$(_context2) {
              while (1) switch (_context2.prev = _context2.next) {
                case 0:
                  return _context2.abrupt("return", new Promise(function (resolve, reject) {
                    var checkLoop = setInterval(function () {
                      if (_this3.isGame && _this3.isServer && _this3.isServerAPI) {
                        resolve();
                        clearInterval(checkLoop);
                      }
                    }, 100);
                  }));
                case 1:
                case "end":
                  return _context2.stop();
              }
            }, _callee2);
          }));
          function checkLanguage(_x) {
            return _checkLanguage.apply(this, arguments);
          }
          return checkLanguage;
        }();
        _proto.getTypeData = function getTypeData(_type) {
          switch (_type) {
            case LangType.Game:
              return this.gameData;
            case LangType.Server:
              return this.serverData;
            case LangType.ServerAPI:
              return this.serverAPIData;
          }
        };
        _proto.switchLoad = function switchLoad(libPath) {
          // console.log("開始讀");
          if (Plug.PublicModel.getInstance.checkApp()) {
            this.JsonData(libPath, this.loadLanguageEnd.bind(this));
          } else {
            libPath = libPath + ".json?/" + new Date().getTime();
            this.RomoteData(libPath, this.loadLanguageEnd.bind(this));
          }
        };
        _proto.loadLanguageEnd = function loadLanguageEnd(jsonText, url) {
          console.log("loadLanguageEnd");
          var type;
          if (url.indexOf("gameLanguage") > 0) type = LangType.Game;
          if (url.indexOf("serverLanguage") > 0) type = LangType.Server;
          if (url.indexOf("serverApiLanguage") > 0) type = LangType.ServerAPI;
          var jsonToObj = JSON.parse(jsonText);
          this.setDate(jsonToObj, type); //設定語言   
          //  SocketSetting.getInstancesetLang(MyWebSocket.instence.Language).init(jsonTo, type); //設定語言   
          // MainModelUp.instance.IsLoadLanguage = true;
        };

        _proto.loadLanguageError = function loadLanguageError(url, err) {
          // console.log("loadLanguageError");
          if (err) console.log("錯誤?" + err);
          this.loadCount++;
          if (this.loadCount > 3) {
            console.error("載入資源失敗");
            return;
          }
          this.JsonData(url, this.loadLanguageEnd.bind(this));
        };
        _proto.loadLanguageErrorAgain = function loadLanguageErrorAgain(url) {
          console.error("语言包下载失败请通知客服");
          // GameControll.getInstance.messaggeState(MessageCommend.BackHome, "資源包有問題，請洽客服")
          // Panel_Message.showConfirm(this, 1,  SocketSetting.getInstance.t("S_9077"), (e) => {
          //     this.onBackHome();
          // }); //"语言包下载失败请通知客服";
          // MainModelUp.instance.ShowMessageBox = true;
        };

        _proto.RomoteData = function RomoteData(url, callback) {
          var url = url;
          console.log('downloadText.url:', url);
          if (callback) {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', url, true);
            if (xhr.overrideMimeType) xhr.overrideMimeType('text\/plain; charset=utf-8');
            xhr.onload = function () {
              if (xhr.readyState === 4) {
                if (xhr.status === 200 || xhr.status === 0) {
                  callback(xhr.response, url);
                }
              } else {
                console.error("資源載入錯誤");
                return;
              }
            };
            xhr.send(null);
          }
        };
        _proto.JsonData = function JsonData(url, callback) {
          console.log('downloadText.url:', url);
          resources.load(url, JsonAsset, function (err, _data) {
            if (err) {
              console.error("資源載入錯誤");
              return;
            }
            callback(JSON.stringify(_data.json), url);
            console.log(_data);
          });
        };
        _proto.checkLanguagePath = function checkLanguagePath() {
          if (Plug.PublicModel.getInstance.checkApp()) return "lib"; // 語言包路徑
          else if (window.isVAServer || window.isInpokerServer) return "../../lib/";else if (window.isGitServer) return "https://wmrd01.github.io/BaccaratPlay/lib/";else
            //預設 // 本地端
            return "http://127.0.0.1/JaiJaiTest/lib/";
        };
        _proto.getLanguage = function getLanguage() {
          var lang = '';
          var isApp = Plug.PublicModel.getInstance.checkApp();
          if (window.GameServerSocket != null) {
            lang = window.lang;
          } else if (isApp) {
            lang = sys.localStorage.getItem('Language');
          } else {
            try {
              //@ts-ignore
              lang = Plug.PublicModel.getInstance.handleURLData(window.location.href).lang;
            } catch (error) {
              lang = 'NTD';
            }
          }
          if (Plug.PublicModel.getInstance.checkStringNull(lang)) lang = 'NTD';
          if (isApp) sys.localStorage.setItem('Language', lang);
          return lang;
        };
        return LanguageManager;
      }(BaseSingleton()));
      var LangType = exports('LangType', /*#__PURE__*/function (LangType) {
        LangType[LangType["Game"] = 0] = "Game";
        LangType[LangType["Server"] = 1] = "Server";
        LangType[LangType["ServerAPI"] = 2] = "ServerAPI";
        return LangType;
      }({}));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/length.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decodeLength: decodeLength,
        encodeLength: encodeLength
      });
      cclegacy._RF.push({}, "cf345jH1O1B2qRfOWaxYb4/", "length", undefined);
      function encodeLength(x) {
        var output = [];
        do {
          var encodedByte = x % 128;
          x = Math.floor(x / 128);
          if (x > 0) {
            encodedByte = encodedByte | 128;
          }
          output.push(encodedByte);
        } while (x > 0);
        return output;
      }
      function decodeLength(buffer, startIndex) {
        var i = startIndex;
        var encodedByte = 0;
        var value = 0;
        var multiplier = 1;
        do {
          encodedByte = buffer[i++];
          value += (encodedByte & 127) * multiplier;
          if (multiplier > 128 * 128 * 128) {
            throw Error("malformed length");
          }
          multiplier *= 128;
        } while ((encodedByte & 128) != 0);
        return {
          length: value,
          bytesUsedToEncodeLength: i - startIndex
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/LookTex.ts", ['cc'], function (exports) {
  var cclegacy, _decorator, dynamicAtlasManager, instantiate, SpriteFrame, find, Sprite, Node;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      dynamicAtlasManager = module.dynamicAtlasManager;
      instantiate = module.instantiate;
      SpriteFrame = module.SpriteFrame;
      find = module.find;
      Sprite = module.Sprite;
      Node = module.Node;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "57321kgPTtPpa1Wpj92iKoy", "LookTex", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;

      /**
       * Predefined variables
       * Name = LookTex
       * DateTime = Wed Jun 12 2024 16:06:49 GMT+0800 (台北標準時間)
       * Author = sboy61017
       * FileBasename = LookTex.ts
       * FileBasenameNoExtension = LookTex
       * URL = db://assets/resources/prefab/TexDebug/LookTex.ts
       * ManualUrl = https://docs.cocos.com/creator/3.4/manual/en/
       *
       */

      var LookTex = exports('LookTex', (_dec = ccclass('LookTex'), _dec(_class = /*#__PURE__*/function () {
        function LookTex(_item, _sv) {
          this.item = void 0;
          this.sv = void 0;
          /**渲染目標 */
          this.renderCanvas = void 0;
          this.isReset = false;
          this.index_sp = 0;
          this.index_label = 0;
          console.log(_item, _sv);
          this.item = _item;
          this.sv = _sv;
          this.sv.node.on(Node.EventType.TOUCH_MOVE, this.setSwallow, this);
          this.sv.node.on(Node.EventType.TOUCH_START, this.setSwallow, this);
          this.sv.node.on(Node.EventType.TOUCH_END, this.setSwallow, this);
          this.sv.node.on(Node.EventType.TOUCH_CANCEL, this.setSwallow, this);
          this.sv.node.active = false;
          this.sv.content.removeAllChildren();
        }
        var _proto = LookTex.prototype;
        _proto.setRenderTarget = function setRenderTarget(_node) {
          this.renderCanvas = _node;
          return this;
        }
        /**重新刷新合批 */;
        _proto.reset = function reset() {
          var _this = this;
          if (this.isReset) return;
          this.isReset = true;
          this.index_sp = 0;
          this.index_label = 0;
          this.sv.content.removeAllChildren();
          //@ts-ignore
          cc.director.getScheduler().schedule(function () {
            _this.renderCanvas.active = false;
            dynamicAtlasManager.reset();
            _this.renderCanvas.active = true;
            //@ts-ignore
            cc.director.getScheduler().schedule(function () {
              for (var index = 0; index < dynamicAtlasManager['_atlases'].length; index++) {
                _this.add(dynamicAtlasManager['_atlases'], _this.index_sp);
                _this.index_sp++;
              }
              /**文字合批的地方 */
              if (dynamicAtlasManager['_atlases_label']) for (var _index = 0; _index < dynamicAtlasManager['_atlases_label'].length; _index++) {
                _this.add(dynamicAtlasManager['_atlases_label'], _this.index_label);
                _this.index_label++;
              }
              _this.isReset = false;
            }, _this.sv, 0, 0, 0, false);
          }, this.sv, 0, 0, 0, false);
        };
        _proto.add = function add(path, index) {
          var tex = instantiate(this.item);
          var sf = new SpriteFrame();
          sf.texture = path[index]['_texture'];
          find('Sprite', tex).getComponent(Sprite).spriteFrame = sf;
          this.sv.content.addChild(tex);
        };
        _proto.checkLength = function checkLength() {
          if (this.index_sp != dynamicAtlasManager['_atlases'].length && !this.isReset) {
            this.add(dynamicAtlasManager['_atlases'], this.index_sp);
            this.index_sp++;
          }
          /**文字合批的地方 */
          if (dynamicAtlasManager['_atlases_label']) if (this.index_label != dynamicAtlasManager['_atlases_label'].length && !this.isReset) {
            this.add(dynamicAtlasManager['_atlases_label'], this.index_label);
            this.index_label++;
          }
        };
        _proto.update = function update(dt) {
          if (this.index_sp != dynamicAtlasManager['_atlases'].length && !this.isReset) {
            this.add(dynamicAtlasManager['_atlases'], this.index_sp);
            this.index_sp++;
          }
          /**文字合批的地方 */
          if (dynamicAtlasManager['_atlases_label']) if (this.index_label != dynamicAtlasManager['_atlases_label'].length && !this.isReset) {
            this.add(dynamicAtlasManager['_atlases_label'], this.index_label);
            this.index_label++;
          }
        };
        _proto.setSwallow = function setSwallow(e) {
          e.preventSwallow = true;
        };
        return LookTex;
      }()) || _class));
      /**
       * [1] Class member could be defined like this.
       * [2] Use `property` decorator if your want the member to be serializable.
       * [3] Your initialization goes here.
       * [4] Your update function goes here.
       *
       * Learn more about scripting: https://docs.cocos.com/creator/3.4/manual/en/scripting/
       * Learn more about CCClass: https://docs.cocos.com/creator/3.4/manual/en/scripting/decorator.html
       * Learn more about life-cycle callbacks: https://docs.cocos.com/creator/3.4/manual/en/scripting/life-cycle-callbacks.html
       */
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10Bonus.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './M10SFBonus.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Layout, M10SFBonus;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Layout = module.Layout;
    }, function (module) {
      M10SFBonus = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "a1540Eqk6FFcY5rIGWMqJox", "M10Bonus", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10Bonus = exports('default', (_dec = ccclass('M10Bonus'), _dec2 = property({
        type: Layout
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_M10SFBonus) {
        _inheritsLoose(M10Bonus, _M10SFBonus);
        function M10Bonus() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _M10SFBonus.call.apply(_M10SFBonus, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "layout", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = M10Bonus.prototype;
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          _M10SFBonus.prototype.orientationEvent.call(this, isLandscape);
          if (isLandscape) {
            this.layout.spacingY = 38.15;
          } else {
            this.layout.spacingY = 52.55;
          }
        };
        return M10Bonus;
      }(M10SFBonus), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "layout", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10Dice.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './M10SFGamer.ts', './BasicEnum.ts', './CommonValue.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Vec3, Sprite, Color, tween, v3, IdentityType, M10SFGamer, Platform, CommonValue;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Vec3 = module.Vec3;
      Sprite = module.Sprite;
      Color = module.Color;
      tween = module.tween;
      v3 = module.v3;
    }, function (module) {
      IdentityType = module.IdentityType;
      M10SFGamer = module.default;
    }, function (module) {
      Platform = module.Platform;
    }, function (module) {
      CommonValue = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _class, _class2, _descriptor, _descriptor2, _descriptor3;
      cclegacy._RF.push({}, "845acdL07NNv5+V8KYDnNzk", "M10Dice", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10Dice = exports('default', (_dec = ccclass('M10Dice'), _dec2 = property({
        group: {
          name: Platform.Mobile
        },
        type: Vec3,
        visible: function visible() {
          this.mobile_DicePositions.length = this.dices.length;
          for (var index = 0; index < this.mobile_DicePositions.length; index++) {
            if (!this.mobile_DicePositions[index]) this.mobile_DicePositions[index] = Vec3.ZERO;
          }
          return true;
        }
      }), _dec3 = property({
        group: {
          name: Platform.Web
        },
        type: Vec3,
        visible: function visible() {
          this.web_DicePositions.length = this.dices.length;
          for (var index = 0; index < this.web_DicePositions.length; index++) {
            if (!this.web_DicePositions[index]) this.web_DicePositions[index] = Vec3.ZERO;
          }
          return true;
        }
      }), _dec4 = property(Sprite), _dec(_class = (_class2 = /*#__PURE__*/function (_M10SFGamer) {
        _inheritsLoose(M10Dice, _M10SFGamer);
        function M10Dice() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _M10SFGamer.call.apply(_M10SFGamer, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "mobile_DicePositions", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "web_DicePositions", _descriptor2, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "dices", _descriptor3, _assertThisInitialized(_this));
          _this._cb = null;
          _this.quadraticCurve = function (t, p1, cp, p2, out) {
            out.x = (1 - t) * (1 - t) * p1.x + 2 * t * (1 - t) * cp.x + t * t * p2.x;
            out.y = (1 - t) * (1 - t) * p1.y + 2 * t * (1 - t) * cp.y + t * t * p2.y;
            out.z = (1 - t) * (1 - t) * p1.z + 2 * t * (1 - t) * cp.z + t * t * p2.z;
          };
          return _this;
        }
        var _proto = M10Dice.prototype;
        _proto.initDice = function initDice() {
          for (var index = 0; index < this.dices.length; index++) {
            this.dices[index].spriteFrame = this.orientationSprite[CommonValue.platform + "_DiceDefault"];
            this.dices[index].color = Color.WHITE;
            this.dices[index].node.setPosition(this[CommonValue.platform + "_DicePositions"][index]);
          }
        };
        _proto.setDice = function setDice(showDices) {
          // this.currentDice = dice
          var diceIndex = 0;
          for (var index = 0; index < this.dices.length; index++) {
            if (this.dices[index].color.a == 0) continue; /**隱藏的圖片不必檢查 */
            if (showDices[diceIndex] == 0) this.dices[index].spriteFrame = this.orientationSprite[CommonValue.platform + "_DiceDefault"];else this.dices[index].spriteFrame = this.spriteFrames.get(showDices[diceIndex]);
            diceIndex++;
          }
        };
        _proto.rollDice = function rollDice(dicesNum, cb) {
          var _this2 = this;
          this._cb = cb;
          var diceIndex = 0;
          console.log(dicesNum);
          var _loop = function _loop(index) {
            console.log(index, _this2.dices[index].color.a);
            if (_this2.dices[index].color.a == 0) return 1; // continue
            var getDiceIndex = diceIndex;
            tween(_this2.dices[index]).to(.5, {
              color: new Color(255, 255, 255, 0)
            }).call(function (t) {
              return _this2.showDices(t, getDiceIndex, dicesNum[getDiceIndex], _this2[CommonValue.platform + "_DicePositions"][index], getDiceIndex == dicesNum.length - 1, dicesNum.length == 1);
            }).start();
            tween(_this2.dices[index].node).by(.5, {
              position: v3(0, 50)
            }).start();
            diceIndex++;
          };
          for (var index = 0; index < this.dices.length; index++) {
            if (_loop(index)) continue;
          }
        };
        _proto.showDices = function showDices(target, index, dicesNum, dicesPos, isLast, isOnly) {
          var _this3 = this;
          if (isLast === void 0) {
            isLast = false;
          }
          if (isOnly === void 0) {
            isOnly = false;
          }
          target.color = Color.WHITE;
          var posX = this.identity == IdentityType.Enemy ? -100 : 100;
          if (isOnly) target.spriteFrame = this.orientationSprite[CommonValue.platform + "_DiceDefault"];else target.spriteFrame = dicesNum == 0 ? this.orientationSprite[CommonValue.platform + "_DiceDefault"] : this.spriteFrames.get(dicesNum);
          tween(target.node).set({
            position: v3(posX, 100),
            scale: Vec3.ZERO
          }).delay(.5 + index).to(.5, {
            position: v3(posX, -300),
            scale: Vec3.ONE
          }).delay(.5).to(.5, {
            position: dicesPos
          }).call(function () {
            if (isLast || isOnly) _this3._cb();
            // if (index == this.dices.length - 1 && this._cb) this._cb()
          }).start();
        };
        _proto.filterDices = function filterDices(_filterDices, cb) {
          var _this4 = this;
          var diceIndex = 0;
          var _loop2 = function _loop2() {
              var dice = _this4.dices[index];
              if (dice.color.a == 0) return 0; // continue
              /**已經隱藏的不需要訪問 */
              var isLast = diceIndex == _filterDices.length - 1; /**確認是否最後一顆骰 */

              if (!isLast && typeof _filterDices[diceIndex] == 'number') {
                diceIndex++;
                return 0; // continue
                /**如果不是最後一顆骰而且有數字的話就跳過，因為不用做事情 */
              }
              /**如果是過濾掉骰子要掛上動畫 */
              if (_filterDices[diceIndex] == null) {
                var x = _this4.identity == IdentityType.Enemy ? -100 : 100;
                var startPos = dice.node.position;
                var controlPos = v3(startPos.x + x / 2, startPos.y + 70, 0);
                var endPos = v3(startPos.x + x, startPos.y + 50, 0);
                var tempVec3 = v3();
                tween(dice).delay(1).parallel(tween(dice.node).by(.5, {
                  position: endPos
                }, {
                  onUpdate: function onUpdate(target, ratio) {
                    _this4.quadraticCurve(ratio, startPos, controlPos, endPos, tempVec3);
                    dice.node.setPosition(tempVec3);
                  }
                }), tween(dice).to(.5, {
                  color: new Color(255, 255, 255, 0)
                })).start();
              }
              if (isLast) {
                /**如果是最後一顆，不管怎樣設定倒時結束 */
                tween(_this4).delay(1.6).call(cb).start();
                return {
                  v: void 0
                };
              }
              diceIndex++;
            },
            _ret;
          for (var index = 0; index < this.dices.length; index++) {
            _ret = _loop2();
            if (_ret === 0) continue;
            if (_ret) return _ret.v;
          }
        };
        return M10Dice;
      }(M10SFGamer), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mobile_DicePositions", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return [];
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "web_DicePositions", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return [];
        }
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "dices", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return [];
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10Enum.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BasicEnum.ts'], function (exports) {
  var _extends, cclegacy, BasicTweenTag;
  return {
    setters: [function (module) {
      _extends = module.extends;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BasicTweenTag = module.BasicTweenTag;
    }],
    execute: function () {
      cclegacy._RF.push({}, "e75actogQpIFbV8hNr3E+09", "M10Enum", undefined);
      var M4Enum = exports('M4Enum', _extends({}, BasicTweenTag, {
        PokerShow: 100
      }));
      var M10Select = exports('M10Select', /*#__PURE__*/function (M10Select) {
        M10Select["Red"] = "Red";
        M10Select["Black"] = "Black";
        M10Select["Odd"] = "Odd";
        M10Select["Even"] = "Even";
        M10Select["Big"] = "Big";
        M10Select["Small"] = "Small";
        return M10Select;
      }({}));
      var PanelIndex = exports('PanelIndex', /*#__PURE__*/function (PanelIndex) {
        PanelIndex[PanelIndex["BG"] = 0] = "BG";
        PanelIndex[PanelIndex["Bonus"] = 1] = "Bonus";
        PanelIndex[PanelIndex["BetInfo"] = 2] = "BetInfo";
        PanelIndex[PanelIndex["Chip"] = 3] = "Chip";
        PanelIndex[PanelIndex["BetSelect"] = 4] = "BetSelect";
        PanelIndex[PanelIndex["GameShow"] = 5] = "GameShow";
        PanelIndex[PanelIndex["AutoPlay"] = 6] = "AutoPlay";
        PanelIndex[PanelIndex["Version"] = 7] = "Version";
        return PanelIndex;
      }({}));
      var GameResult = exports('GameResult', /*#__PURE__*/function (GameResult) {
        GameResult[GameResult["Win"] = 0] = "Win";
        GameResult[GameResult["Lose"] = 1] = "Lose";
        GameResult[GameResult["Tie"] = 2] = "Tie";
        return GameResult;
      }({}));
      var GameEnum = exports('GameEnum', /*#__PURE__*/function (GameEnum) {
        GameEnum[GameEnum["SelectBtnsActive"] = 0] = "SelectBtnsActive";
        GameEnum[GameEnum["EnemySelect"] = 1] = "EnemySelect";
        GameEnum[GameEnum["CheckOrder"] = 2] = "CheckOrder";
        GameEnum[GameEnum["CheckSelect"] = 3] = "CheckSelect";
        GameEnum[GameEnum["SendAPI"] = 4] = "SendAPI";
        return GameEnum;
      }({}));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10Gamer.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './M10SFGamer.ts', './CommonValue.ts', './M10Dice.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Sprite, Tween, v3, tween, randomRange, Vec3, IdentityType, CommonValue, M10Dice;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Sprite = module.Sprite;
      Tween = module.Tween;
      v3 = module.v3;
      tween = module.tween;
      randomRange = module.randomRange;
      Vec3 = module.Vec3;
    }, function (module) {
      IdentityType = module.IdentityType;
    }, function (module) {
      CommonValue = module.default;
    }, function (module) {
      M10Dice = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "252aaxrXQVN36cb6LOEhPEo", "M10Gamer", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10Gamer = exports('default', (_dec = ccclass('M10Gamer'), _dec2 = property({
        type: Sprite,
        tooltip: "人物圖片"
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_M10Dice) {
        _inheritsLoose(M10Gamer, _M10Dice);
        function M10Gamer() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _M10Dice.call.apply(_M10Dice, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "spCharacter", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = M10Gamer.prototype;
        _proto.init = function init() {
          this.initDice();
          Tween.stopAllByTarget(this.spCharacter.node);
          this.spCharacter.node.setPosition(v3(0, -82));
          this.spCharacter.node.angle = 0;
          // this.winAction()
          // this.lostAction()
        };

        _proto.winAction = function winAction() {
          var _this2 = this;
          var startAngle = this.node.angle;
          var action = tween(this.spCharacter.node).by(.1, {
            position: v3(0, 50, 0)
          });
          for (var index = 0; index < 7; index++) {
            var offsetAngle = this.identity == IdentityType.Enemy ? randomRange(-30, 10) : randomRange(-10, 30);
            action.to(0.05, {
              angle: startAngle + offsetAngle
            });
          }
          action.to(0.05, {
            angle: 0
          }).by(.1, {
            position: v3(0, -50, 0)
          }, {
            onComplete: function onComplete() {
              return _this2.winAction();
            }
          }).start();
        };
        _proto.lostAction = function lostAction() {
          var _this3 = this;
          this.spCharacter.node.angle = this.identity == IdentityType.Enemy ? 45 : -45;
          var x = this.identity == IdentityType.Enemy ? -100 : 100;
          var startPos = this.spCharacter.node.position;
          var controlPos = v3(startPos.x + x / 2, +30, 0);
          var endPos = v3(startPos.x + x, -30, 0);
          var tempVec3 = v3();
          tween(this.spCharacter.node).by(1, {
            position: endPos
          }, {
            onUpdate: function onUpdate(target, ratio) {
              _this3.quadraticCurve(ratio, startPos, controlPos, endPos, tempVec3);
              target.setPosition(tempVec3);
            },
            onComplete: function onComplete() {
              return _this3.spCharacter.node.angle = _this3.identity == IdentityType.Enemy ? 90 : -90;
            }
          }).by(.5, {
            position: v3(this.identity == IdentityType.Enemy ? -50 : 50, 0)
          }).start();
        };
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          _M10Dice.prototype.orientationEvent.call(this, isLandscape);
          for (var index = 0; index < this.dices.length; index++) {
            var getPos = this[CommonValue.platform + "_DicePositions"][index] ? this[CommonValue.platform + "_DicePositions"][index] : Vec3.ZERO;
            this.dices[index].node.setPosition(getPos);
          }
          //原本的圖片要替換掉
          // this.setCardSprite(this.currentCard)
        };

        return M10Gamer;
      }(M10Dice), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "spCharacter", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10PanelAutoPlay.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './M10Enum.ts', './BasicAutoPlay.ts', './BasicPlaySelect.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, PanelIndex, BasicAutoPlay, Select;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      PanelIndex = module.PanelIndex;
    }, function (module) {
      BasicAutoPlay = module.default;
    }, function (module) {
      Select = module.Select;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "4a1bfMrTxtDQaYazWEAR5Qu", "M10PanelAutoPlay", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10PanelAutoPlay = exports('default', (_dec = ccclass('M10PanelAutoPlay'), _dec(_class = /*#__PURE__*/function (_BasicAutoPlay) {
        _inheritsLoose(M10PanelAutoPlay, _BasicAutoPlay);
        function M10PanelAutoPlay() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BasicAutoPlay.call.apply(_BasicAutoPlay, [this].concat(args)) || this;
          _this.selectBet = Select.Play;
          return _this;
        }
        var _proto = M10PanelAutoPlay.prototype;
        _proto.onLoad = function onLoad() {
          this.zIndex = PanelIndex.AutoPlay;
          _BasicAutoPlay.prototype.onLoad.call(this);
        };
        return M10PanelAutoPlay;
      }(BasicAutoPlay)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10PanelBetInfo.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './M10Enum.ts', './BasicSFBetInfo.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, v3, Vec3, PanelIndex, BasicSFBetInfo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      v3 = module.v3;
      Vec3 = module.Vec3;
    }, function (module) {
      PanelIndex = module.PanelIndex;
    }, function (module) {
      BasicSFBetInfo = module.default;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "7ea7bSNiRtBk4lPMc8EcMue", "M10PanelBetInfo", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10PanelBetInfo = exports('default', (_dec = ccclass('PanelBetInfo'), _dec(_class = /*#__PURE__*/function (_BasicSFBetInfo) {
        _inheritsLoose(M10PanelBetInfo, _BasicSFBetInfo);
        function M10PanelBetInfo() {
          return _BasicSFBetInfo.apply(this, arguments) || this;
        }
        var _proto = M10PanelBetInfo.prototype;
        _proto.onLoad = function onLoad() {
          this.zIndex = PanelIndex.BetInfo;
          _BasicSFBetInfo.prototype.onLoad.call(this);
        };
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          _BasicSFBetInfo.prototype.orientationEvent.call(this, isLandscape);
          if (isLandscape) {
            this.btnTurbo.node.setPosition(v3(-394, 0));
            this.btnAutoPlay.node.parent.setPosition(v3(394, 0));
            this.btnMinus.node.setPosition(v3(-257, 0));
            this.btnPlus.node.setPosition(v3(257, 0));
            this.spriteTotalBg.enabled = false;
            this.spriteTotalBg.node.setPosition(Vec3.ZERO);
            this.labelTotalBet.fontSize = 60;
            this.labelTotalBet.lineHeight = 60;
            this.labelAutoCount.fontSize = 40;
            this.labelAutoCount.lineHeight = 40;
            this.labelTotalBet.node.setPosition(Vec3.ZERO);
          } else {
            this.btnTurbo.node.setPosition(v3(-421, -271));
            this.btnAutoPlay.node.parent.setPosition(v3(421, -271));
            this.btnMinus.node.setPosition(v3(-246, -271));
            this.btnPlus.node.setPosition(v3(246, -271));
            this.spriteTotalBg.enabled = true;
            this.spriteTotalBg.node.setPosition(v3(0, -268));
            this.labelTotalBet.fontSize = 90;
            this.labelTotalBet.lineHeight = 90;
            this.labelAutoCount.fontSize = 70;
            this.labelAutoCount.lineHeight = 70;
            this.labelTotalBet.node.setPosition(v3(0, -272));
          }
        };
        return M10PanelBetInfo;
      }(BasicSFBetInfo)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10PanelBetSelect.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './EventMng.ts', './Public.ts', './M10Enum.ts', './M10SFSelect.ts', './CommonValue.ts', './BasicPlaySelect.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _createForOfIteratorHelperLoose, cclegacy, _decorator, EventMng, NotificationType, setFunctionName, Plug, PanelIndex, M10Select, GameEnum, M10SFSelect, CommonValue, Select, BasicPlaySendDate;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      EventMng = module.default;
      NotificationType = module.NotificationType;
    }, function (module) {
      setFunctionName = module.setFunctionName;
      Plug = module.Plug;
    }, function (module) {
      PanelIndex = module.PanelIndex;
      M10Select = module.M10Select;
      GameEnum = module.GameEnum;
    }, function (module) {
      M10SFSelect = module.default;
    }, function (module) {
      CommonValue = module.default;
    }, function (module) {
      Select = module.Select;
      BasicPlaySendDate = module.BasicPlaySendDate;
    }],
    execute: function () {
      var _dec, _class4, _class5;
      cclegacy._RF.push({}, "f2390T9OQZPipjcM/OItZiy", "M10PanelBetSelect", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10PanelBetSelect = exports('default', (_dec = ccclass('M10PanelBetSelect'), _dec(_class4 = (_class5 = /*#__PURE__*/function (_M10SFSelect) {
        _inheritsLoose(M10PanelBetSelect, _M10SFSelect);
        function M10PanelBetSelect() {
          return _M10SFSelect.apply(this, arguments) || this;
        }
        var _proto = M10PanelBetSelect.prototype;
        _proto.onLoad = function onLoad() {
          this.zIndex = PanelIndex.BetSelect;
          this.btnRed.initStatus(true);
          this.btnBlack.initStatus(true);
          this.btnOdd.initStatus(true);
          this.btnEven.initStatus(true);
          this.btnBig.initStatus(true);
          this.btnSmall.initStatus(true);
          this.setBtnMap(M10Select, this.btnRed, this.onSelectItem);
          this.setBtnMap(M10Select, this.btnBlack, this.onSelectItem);
          this.setBtnMap(M10Select, this.btnOdd, this.onSelectItem);
          this.setBtnMap(M10Select, this.btnEven, this.onSelectItem);
          this.setBtnMap(M10Select, this.btnBig, this.onSelectItem);
          this.setBtnMap(M10Select, this.btnSmall, this.onSelectItem);
          this.setSelectEnum(M10Select);
          this.resetSelectBtnSet(false);
          EventMng.getInstance.setEvent(NotificationType.Game, GameEnum.SelectBtnsActive, this.resetSelectBtnSet, this);
          EventMng.getInstance.setEvent(NotificationType.Game, GameEnum.EnemySelect, this.onSelectItem, this);
          // this.btnRed.node.off(Input.EventType.TOUCH_MOVE)
          // this.btnBlack.node.off(Input.EventType.TOUCH_MOVE)
          // this.btnOdd.node.off(Input.EventType.TOUCH_MOVE)
          // this.btnEven.node.off(Input.EventType.TOUCH_MOVE)
          // this.btnBig.node.off(Input.EventType.TOUCH_MOVE)
          // this.btnSmall.node.off(Input.EventType.TOUCH_MOVE)

          _M10SFSelect.prototype.onLoad.call(this);
        };
        _proto.start = function start() {
          this.getCompo(Select.Play).node.active = true;
        };
        _proto.updateSelection = function updateSelection(e, customEventData) {
          if (!Plug.Model.checkHasEnum(M10Select, customEventData) && !Plug.Model.checkHasEnum(Select, customEventData)) throw new Error("node\u7269\u4EF6\u547D\u540D\u6709\u554F\u984C\uFF0CEvnetData\uFF1A" + customEventData);
          this.getCompo(Select.Play).node.active = false;
          // this.resetSelectBtnSet(true)
        };

        _proto.processGameFlow = function processGameFlow() {
          if (CommonValue.isAuto) this.loopGame();else EventMng.getInstance.emit(NotificationType.Game, GameEnum.SendAPI, this.rememberDate, GameEnum.CheckOrder);
        };
        _proto.PacketBuild = function PacketBuild() {
          this.rememberDate = new SendCheckOrder();
        };
        _proto.loopGame = function loopGame() {
          // this.resetSelectBtnSet(true)
          // super.loopGame()
        }
        /**不包含Play按鈕 */;
        _proto.resetSelectBtnSet = function resetSelectBtnSet(bool, isInteractable) {
          if (isInteractable === void 0) {
            isInteractable = true;
          }
          for (var _iterator = _createForOfIteratorHelperLoose(this.mapAllBtn), _step; !(_step = _iterator()).done;) {
            var _step$value = _step.value,
              key = _step$value[0],
              value = _step$value[1];
            if (key == Select.Play) continue;
            value.node.active = bool;
            value.interactable = isInteractable;
          }
        };
        _proto.showWinEnd = function showWinEnd() {
          _M10SFSelect.prototype.showWinEnd.call(this);
          this.resetSelectBtnSet(false);
          this.getCompo(Select.Play).node.active = true;
        };
        _proto.onSelectItem = function onSelectItem(e, customEventData) {
          if (!Plug.Model.checkHasEnum(M10Select, customEventData) && !Plug.Model.checkHasEnum(Select, customEventData)) throw new Error("node\u7269\u4EF6\u547D\u540D\u6709\u554F\u984C\uFF0CEvnetData\uFF1A" + customEventData);
          this.resetSelectBtnSet(true, false);
          var btn = this.getCompo(customEventData);
          btn.interactable = true;
          this.changeBtnStatus(btn, true);
          //TODO 傳遞給後端
          var selectData = new SendSelect();
          selectData.roundSelect = customEventData;
          EventMng.getInstance.emit(NotificationType.Game, GameEnum.SendAPI, selectData, GameEnum.CheckSelect);
        };
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          _M10SFSelect.prototype.orientationEvent.call(this, isLandscape);
        };
        return M10PanelBetSelect;
      }(M10SFSelect), _applyDecoratedDescriptor(_class5.prototype, "onSelectItem", [setFunctionName], Object.getOwnPropertyDescriptor(_class5.prototype, "onSelectItem"), _class5.prototype), _class5)) || _class4));
      var M10SendDate = exports('M10SendDate', /*#__PURE__*/function (_BasicPlaySendDate) {
        _inheritsLoose(M10SendDate, _BasicPlaySendDate);
        function M10SendDate() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BasicPlaySendDate.call.apply(_BasicPlaySendDate, [this].concat(args)) || this;
          _this.select = void 0;
          return _this;
        }
        return M10SendDate;
      }(BasicPlaySendDate));
      var SendSelect = exports('SendSelect', function SendSelect() {
        this.roundSelect = void 0;
      });
      var SendCheckOrder = exports('SendCheckOrder', function SendCheckOrder() {
        this.order = void 0;
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10PanelBG.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './M10Enum.ts', './M10SFBG.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Sprite, UITransform, size, PanelIndex, M10SFBG;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Sprite = module.Sprite;
      UITransform = module.UITransform;
      size = module.size;
    }, function (module) {
      PanelIndex = module.PanelIndex;
    }, function (module) {
      M10SFBG = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "49e82qqOHJOK4hJToSYEuQ1", "M10PanelBG", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10PanelBG = exports('default', (_dec = ccclass('M10PanelBG'), _dec2 = property(Sprite), _dec(_class = (_class2 = /*#__PURE__*/function (_M4SFBG) {
        _inheritsLoose(M10PanelBG, _M4SFBG);
        function M10PanelBG() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _M4SFBG.call.apply(_M4SFBG, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "bg", _descriptor, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = M10PanelBG.prototype;
        _proto.onLoad = function onLoad() {
          this.zIndex = PanelIndex.BG;
          _M4SFBG.prototype.onLoad.call(this);
        };
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          this.bg.sizeMode = isLandscape ? Sprite.SizeMode.TRIMMED : Sprite.SizeMode.CUSTOM;
          this.bg.spriteFrame = isLandscape ? this.orientationSprite.web_bg : this.orientationSprite.mobile_bg;
          if (!isLandscape) this.bg.getComponent(UITransform).setContentSize(size(1080, 2337));
        };
        return M10PanelBG;
      }(M10SFBG), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "bg", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10PanelBonus.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './M10Enum.ts', './M10Bonus.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, v3, BaseComponent, PanelIndex, M10Bonus;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      v3 = module.v3;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      PanelIndex = module.PanelIndex;
    }, function (module) {
      M10Bonus = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "6f69cnrM4xKVZ3kzvSys1/U", "M10PanelBonus", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10PanelBonus = exports('default', (_dec = ccclass('M10PanelBonus'), _dec2 = property(M10Bonus), _dec3 = property(M10Bonus), _dec(_class = (_class2 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(M10PanelBonus, _BaseComponent);
        function M10PanelBonus() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "left", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "right", _descriptor2, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = M10PanelBonus.prototype;
        _proto.onLoad = function onLoad() {
          this.zIndex = PanelIndex.Bonus;
          _BaseComponent.prototype.onLoad.call(this);
        };
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          if (isLandscape) {
            this.left.node.setPosition(v3(-201, 119));
            this.right.node.setPosition(v3(201, 119));
          } else {
            this.left.node.setPosition(v3(-432, 462));
            this.right.node.setPosition(v3(432, 462));
          }
        };
        return M10PanelBonus;
      }(BaseComponent), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "left", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "right", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10PanelChip.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './M10Enum.ts', './BasicChip.ts'], function (exports) {
  var _inheritsLoose, _asyncToGenerator, _regeneratorRuntime, cclegacy, _decorator, size, Vec3, v3, PanelIndex, BasicChip;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      size = module.size;
      Vec3 = module.Vec3;
      v3 = module.v3;
    }, function (module) {
      PanelIndex = module.PanelIndex;
    }, function (module) {
      BasicChip = module.default;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "2e1deC2lx5AwZUgspMLC4+7", "M10PanelChip", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10PanelChip = exports('default', (_dec = ccclass('M10PanelChip'), _dec(_class = /*#__PURE__*/function (_BasicChip) {
        _inheritsLoose(M10PanelChip, _BasicChip);
        function M10PanelChip() {
          return _BasicChip.apply(this, arguments) || this;
        }
        var _proto = M10PanelChip.prototype;
        _proto.onLoad = function onLoad() {
          this.zIndex = PanelIndex.Chip;
          _BasicChip.prototype.onLoad.call(this);
        };
        _proto.start = /*#__PURE__*/function () {
          var _start = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  _context.next = 2;
                  return _BasicChip.prototype.start.call(this);
                case 2:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function start() {
            return _start.apply(this, arguments);
          }
          return start;
        }();
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          //這邊只能邊用介面調整邊確認數值...
          var bgSizeS = isLandscape ? 54 : 120;
          var labelSize = isLandscape ? 20 : 40;
          var chipDate = isLandscape ? this.deskTopChipInfo : this.mobileChipInfo;
          this.mapChip.forEach(function (val) {
            if (val.btn.node.getSiblingIndex() >= chipDate.length) val.btn.node.active = false;else val.btn.node.active = true;
            val.ui.setContentSize(size(bgSizeS, bgSizeS));
            val.label.fontSize = labelSize;
          });
          this.layoutChip.setPosition(isLandscape ? Vec3.ZERO : v3(0, -360, 0));
        };
        return M10PanelChip;
      }(BasicChip)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10PanelGameShow.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './EventMng.ts', './M10Enum.ts', './M10SFGamer.ts', './BasicGameShow.ts', './M10Gamer.ts'], function (exports) {
  var _applyDecoratedDescriptor, _initializerDefineProperty, _inheritsLoose, _assertThisInitialized, _asyncToGenerator, _regeneratorRuntime, cclegacy, _decorator, Sprite, SpriteFrame, Label, tween, v3, Vec3, EventMng, NotificationType, GameEnum, PanelIndex, IdentityType, BasicGameShow, M10Gamer;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _initializerDefineProperty = module.initializerDefineProperty;
      _inheritsLoose = module.inheritsLoose;
      _assertThisInitialized = module.assertThisInitialized;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Sprite = module.Sprite;
      SpriteFrame = module.SpriteFrame;
      Label = module.Label;
      tween = module.tween;
      v3 = module.v3;
      Vec3 = module.Vec3;
    }, function (module) {
      EventMng = module.default;
      NotificationType = module.NotificationType;
    }, function (module) {
      GameEnum = module.GameEnum;
      PanelIndex = module.PanelIndex;
    }, function (module) {
      IdentityType = module.IdentityType;
    }, function (module) {
      BasicGameShow = module.default;
    }, function (module) {
      M10Gamer = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _class, _class2, _descriptor, _descriptor2, _descriptor3, _dec5, _dec6, _dec7, _dec8, _dec9, _class4, _class5, _descriptor4, _descriptor5, _descriptor6, _descriptor7;
      cclegacy._RF.push({}, "fa2de1KiYlPp4/5YM2e71dp", "M10PanelGameShow", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var Order = (_dec = ccclass('Order'), _dec2 = property(Sprite), _dec3 = property(SpriteFrame), _dec4 = property(SpriteFrame), _dec(_class = (_class2 = function Order() {
        _initializerDefineProperty(this, "sprite", _descriptor, this);
        _initializerDefineProperty(this, "oder0", _descriptor2, this);
        _initializerDefineProperty(this, "oder1", _descriptor3, this);
      }, (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "sprite", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "oder0", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "oder1", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      })), _class2)) || _class);
      var M10PanelGameShow = exports('default', (_dec5 = ccclass('M10PanelGameShow'), _dec6 = property({
        type: M10Gamer,
        tooltip: "Gamer組件"
      }), _dec7 = property({
        type: M10Gamer,
        tooltip: "Gamer組件"
      }), _dec8 = property(Label), _dec9 = property({
        type: Order
      }), _dec5(_class4 = (_class5 = /*#__PURE__*/function (_BasicGameShow) {
        _inheritsLoose(M10PanelGameShow, _BasicGameShow);
        function M10PanelGameShow() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BasicGameShow.call.apply(_BasicGameShow, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "enemy", _descriptor4, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "player", _descriptor5, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "labelResult", _descriptor6, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "order", _descriptor7, _assertThisInitialized(_this));
          _this.responeDate = void 0;
          _this.isRollOrder = false;
          return _this;
        }
        var _proto = M10PanelGameShow.prototype;
        _proto.onLoad = function onLoad() {
          EventMng.getInstance.setEvent(NotificationType.Game, GameEnum.CheckOrder, this.rollOrder, this);
          EventMng.getInstance.setEvent(NotificationType.Game, GameEnum.CheckSelect, this.selectResult, this);
          this.zIndex = PanelIndex.GameShow;
          this.order.sprite.node.active = false;
          _BasicGameShow.prototype.onLoad.call(this);
        };
        _proto.start = /*#__PURE__*/function () {
          var _start = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  this.enemy.init();
                  this.player.init();
                  this.labelResult.string = "歡迎來到塔塔塔";
                  _BasicGameShow.prototype.start.call(this);
                case 4:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function start() {
            return _start.apply(this, arguments);
          }
          return start;
        }();
        _proto.showWin = function showWin(result) {
          if (result.winPoint == 0) {
            this.player.lostAction();
            this.enemy.lostAction();
            this.labelResult.string = "平手";
          } else if (result.winPoint > 0) {
            this.player.winAction();
            this.enemy.lostAction();
            this.labelResult.string = "玩家獲勝";
          } else if (result.winPoint < 0) {
            this.player.lostAction();
            this.enemy.winAction();
            this.labelResult.string = "怪物獲勝";
          }
          tween(this).delay(2).call(this.endShow.bind(this)).start();
        };
        _proto.endShow = function endShow() {
          this.isRollOrder = false;
          _BasicGameShow.prototype.endShow.call(this);
        };
        _proto.rollOrder = function rollOrder(result) {
          var _this2 = this;
          EventMng.getInstance.emit(NotificationType.Game, GameEnum.SelectBtnsActive, false, true);
          var _action = tween(this.order.sprite.node);
          if (!this.isRollOrder) {
            this.labelResult.string = "決定回合順序";
            this.player.init();
            this.enemy.init();
            this.order.sprite.node.active = true;
            this.isRollOrder = true;
            _action.repeat(30, tween().to(.01, {
              scale: v3(1, 0, 1)
            }, {
              onComplete: function onComplete(x) {
                _this2.order.sprite.spriteFrame = _this2.order.oder0;
              }
            }).to(.01, {
              scale: Vec3.ONE
            }).to(.01, {
              scale: v3(1, 0, 1)
            }, {
              onComplete: function onComplete(x) {
                _this2.order.sprite.spriteFrame = _this2.order.oder1;
              }
            }).to(.01, {
              scale: Vec3.ONE
            })).to(.01, {
              scale: v3(1, 0, 1)
            }, {
              onComplete: function onComplete(x) {
                _this2.order.sprite.spriteFrame = _this2.order["oder" + result.order];
              }
            }).to(1, {
              scale: Vec3.ONE
            }).delay(.3);
          }
          _action.call( /*#__PURE__*/_asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee2() {
            var awaitE, awaitP;
            return _regeneratorRuntime().wrap(function _callee2$(_context2) {
              while (1) switch (_context2.prev = _context2.next) {
                case 0:
                  _this2.order.sprite.node.active = false;
                  _this2.labelResult.string = result.order == 0 ? "玩家回合" : "怪物回合";
                  awaitE = new Promise(function (resolve, reject) {
                    return _this2.enemy.rollDice(new Array(result.enemyDice.length).fill(0), resolve);
                  });
                  awaitP = new Promise(function (resolve, reject) {
                    return _this2.player.rollDice(result.playerDice, resolve);
                  });
                  _context2.next = 6;
                  return Promise.all([awaitE, awaitP]);
                case 6:
                  EventMng.getInstance.emit(NotificationType.Game, GameEnum.SelectBtnsActive, true, false);
                  tween(_this2).delay(.5).call(function () {
                    if (result.order == IdentityType.Player_Num) {
                      EventMng.getInstance.emit(NotificationType.Game, GameEnum.SelectBtnsActive, true, true);
                    } else {
                      EventMng.getInstance.emit(NotificationType.Game, GameEnum.EnemySelect, null, result.roundSelect);
                    }
                  }).start();
                case 8:
                case "end":
                  return _context2.stop();
              }
            }, _callee2);
          }))).start();
        };
        _proto.selectResult = /*#__PURE__*/function () {
          var _selectResult = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee3(result) {
            var _this3 = this;
            var awaitE, awaitP;
            return _regeneratorRuntime().wrap(function _callee3$(_context3) {
              while (1) switch (_context3.prev = _context3.next) {
                case 0:
                  this.responeDate = result;
                  this.enemy.setDice(result.enemyDice);
                  this.player.setDice(result.playerDice);
                  awaitE = new Promise(function (resolve, reject) {
                    return _this3.enemy.filterDices(result.changeEnemyDice, resolve);
                  });
                  awaitP = new Promise(function (resolve, reject) {
                    return _this3.player.filterDices(result.changePlayerDice, resolve);
                  });
                  _context3.next = 7;
                  return Promise.all([awaitE, awaitP]);
                case 7:
                  if (result.winPoint != undefined) {
                    this.showWin(result);
                  } else EventMng.getInstance.emit(NotificationType.Game, GameEnum.SendAPI, {}, GameEnum.CheckOrder);
                case 8:
                case "end":
                  return _context3.stop();
              }
            }, _callee3, this);
          }));
          function selectResult(_x) {
            return _selectResult.apply(this, arguments);
          }
          return selectResult;
        }();
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          _BasicGameShow.prototype.orientationEvent.call(this, isLandscape);
          if (isLandscape) {
            this.player.node.setPosition(v3(133, -172));
            this.enemy.node.setPosition(v3(-86, -167));
          }
        };
        return M10PanelGameShow;
      }(BasicGameShow), (_descriptor4 = _applyDecoratedDescriptor(_class5.prototype, "enemy", [_dec6], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor5 = _applyDecoratedDescriptor(_class5.prototype, "player", [_dec7], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor6 = _applyDecoratedDescriptor(_class5.prototype, "labelResult", [_dec8], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor7 = _applyDecoratedDescriptor(_class5.prototype, "order", [_dec9], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new Order();
        }
      })), _class5)) || _class4));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10PanelVersion.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './M10Enum.ts', './BasicVersion.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, PanelIndex, BasicVersion;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      PanelIndex = module.PanelIndex;
    }, function (module) {
      BasicVersion = module.default;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "ba0f6E7/PNGE7/Q4swNUUHK", "M10PanelVersion", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var M10PanelVersion = exports('default', (_dec = ccclass('M10PanelVersion'), _dec(_class = /*#__PURE__*/function (_BasicVersion) {
        _inheritsLoose(M10PanelVersion, _BasicVersion);
        function M10PanelVersion() {
          return _BasicVersion.apply(this, arguments) || this;
        }
        var _proto = M10PanelVersion.prototype;
        _proto.onLoad = function onLoad() {
          this.zIndex = PanelIndex.Version;
        };
        return M10PanelVersion;
      }(BasicVersion)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10SFBG.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './BasicEnum.ts'], function (exports) {
  var _applyDecoratedDescriptor, _initializerDefineProperty, _inheritsLoose, _assertThisInitialized, cclegacy, _decorator, SpriteFrame, BaseComponent, Platform;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _initializerDefineProperty = module.initializerDefineProperty;
      _inheritsLoose = module.inheritsLoose;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      SpriteFrame = module.SpriteFrame;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      Platform = module.Platform;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2, _dec4, _dec5, _class4, _class5, _descriptor3;
      cclegacy._RF.push({}, "d361dYqJbZHibjK4EXYrkd6", "M10SFBG", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var SFBG = (_dec = ccclass("SFBG"), _dec2 = property({
        group: {
          name: Platform.Mobile
        },
        type: SpriteFrame
      }), _dec3 = property({
        group: {
          name: Platform.Web
        },
        type: SpriteFrame
      }), _dec(_class = (_class2 = function SFBG() {
        _initializerDefineProperty(this, "mobile_bg", _descriptor, this);
        _initializerDefineProperty(this, "web_bg", _descriptor2, this);
      }, (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mobile_bg", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "web_bg", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class);
      var M10SFBG = exports('default', (_dec4 = ccclass('M10SFBG'), _dec5 = property(SFBG), _dec4(_class4 = (_class5 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(M10SFBG, _BaseComponent);
        function M10SFBG() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "orientationSprite", _descriptor3, _assertThisInitialized(_this));
          return _this;
        }
        return M10SFBG;
      }(BaseComponent), _descriptor3 = _applyDecoratedDescriptor(_class5.prototype, "orientationSprite", [_dec5], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SFBG();
        }
      }), _class5)) || _class4));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10SFBonus.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './BasicEnum.ts', './CommonValue.ts'], function (exports) {
  var _applyDecoratedDescriptor, _initializerDefineProperty, _inheritsLoose, _assertThisInitialized, cclegacy, _decorator, SpriteFrame, Sprite, BaseComponent, Platform, CommonValue;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _initializerDefineProperty = module.initializerDefineProperty;
      _inheritsLoose = module.inheritsLoose;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      SpriteFrame = module.SpriteFrame;
      Sprite = module.Sprite;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      Platform = module.Platform;
    }, function (module) {
      CommonValue = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2, _dec4, _dec5, _dec6, _class4, _class5, _descriptor3, _descriptor4;
      cclegacy._RF.push({}, "3dc1cbPeahKnYpYAkkVRyMt", "M10SFBonus", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var SFBonus = (_dec = ccclass('SFBonus'), _dec2 = property({
        group: {
          name: Platform.Mobile
        },
        type: SpriteFrame
      }), _dec3 = property({
        group: {
          name: Platform.Web
        },
        type: SpriteFrame
      }), _dec(_class = (_class2 = function SFBonus() {
        _initializerDefineProperty(this, "mobile_Energy", _descriptor, this);
        //<--------------------------------平台分界線-------------------------------------->
        _initializerDefineProperty(this, "web_Energy", _descriptor2, this);
      }, (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mobile_Energy", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SpriteFrame();
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "web_Energy", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SpriteFrame();
        }
      })), _class2)) || _class);
      var M10SFBonus = exports('default', (_dec4 = ccclass('M10SFBonus'), _dec5 = property(SFBonus), _dec6 = property(Sprite), _dec4(_class4 = (_class5 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(M10SFBonus, _BaseComponent);
        function M10SFBonus() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "orientationSprite", _descriptor3, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "energys", _descriptor4, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = M10SFBonus.prototype;
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          for (var index = 0; index < this.energys.length; index++) {
            this.energys[index].spriteFrame = this.orientationSprite[CommonValue.platform + "_Energy"];
          }
          _BaseComponent.prototype.orientationEvent.call(this, isLandscape);
        };
        return M10SFBonus;
      }(BaseComponent), (_descriptor3 = _applyDecoratedDescriptor(_class5.prototype, "orientationSprite", [_dec5], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SFBonus();
        }
      }), _descriptor4 = _applyDecoratedDescriptor(_class5.prototype, "energys", [_dec6], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return [];
        }
      })), _class5)) || _class4));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10SFGamer.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './BasicEnum.ts'], function (exports) {
  var _applyDecoratedDescriptor, _initializerDefineProperty, _inheritsLoose, _assertThisInitialized, cclegacy, _decorator, SpriteFrame, Enum, BaseComponent, Platform;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _initializerDefineProperty = module.initializerDefineProperty;
      _inheritsLoose = module.inheritsLoose;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      SpriteFrame = module.SpriteFrame;
      Enum = module.Enum;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      Platform = module.Platform;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _dec5, _dec6, _dec7, _class, _class2, _descriptor, _descriptor2, _descriptor3, _descriptor4, _descriptor5, _descriptor6, _dec8, _dec9, _dec10, _class4, _class5, _descriptor7, _descriptor8;
      cclegacy._RF.push({}, "6038aq63+1D15Sr/tafu6IN", "M10SFGamer", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      // 花色類型枚舉
      var IdentityType = exports('IdentityType', /*#__PURE__*/function (IdentityType) {
        IdentityType["Player"] = "Player";
        IdentityType["Enemy"] = "Enemy";
        IdentityType[IdentityType["Player_Num"] = 0] = "Player_Num";
        IdentityType[IdentityType["Enemy_Num"] = 1] = "Enemy_Num";
        return IdentityType;
      }({}));
      var SFGamer = (_dec = ccclass("SFGamer"), _dec2 = property({
        group: {
          name: Platform.Mobile
        },
        type: SpriteFrame
      }), _dec3 = property({
        group: {
          name: Platform.Mobile
        },
        type: SpriteFrame
      }), _dec4 = property({
        group: {
          name: Platform.Mobile
        },
        type: SpriteFrame
      }), _dec5 = property({
        group: {
          name: Platform.Web
        },
        type: SpriteFrame
      }), _dec6 = property({
        group: {
          name: Platform.Web
        },
        type: SpriteFrame
      }), _dec7 = property({
        group: {
          name: Platform.Web
        },
        type: SpriteFrame
      }), _dec(_class = (_class2 = function SFGamer() {
        _initializerDefineProperty(this, "mobile_Dice", _descriptor, this);
        _initializerDefineProperty(this, "mobile_DiceDefault", _descriptor2, this);
        _initializerDefineProperty(this, "mobile_Character", _descriptor3, this);
        //<--------------------------------平台分界線-------------------------------------->
        _initializerDefineProperty(this, "web_Dice", _descriptor4, this);
        _initializerDefineProperty(this, "web_DiceDefault", _descriptor5, this);
        _initializerDefineProperty(this, "web_Character", _descriptor6, this);
      }, (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mobile_Dice", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return [];
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "mobile_DiceDefault", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "mobile_Character", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor4 = _applyDecoratedDescriptor(_class2.prototype, "web_Dice", [_dec5], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return [];
        }
      }), _descriptor5 = _applyDecoratedDescriptor(_class2.prototype, "web_DiceDefault", [_dec6], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      }), _descriptor6 = _applyDecoratedDescriptor(_class2.prototype, "web_Character", [_dec7], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return null;
        }
      })), _class2)) || _class);
      var M10SFGamer = exports('default', (_dec8 = ccclass('M10SFGamer'), _dec9 = property({
        type: Enum(IdentityType),
        tooltip: "牌的類別"
      }), _dec10 = property(SFGamer), _dec8(_class4 = (_class5 = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(M10SFGamer, _BaseComponent);
        function M10SFGamer() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "identity", _descriptor7, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "orientationSprite", _descriptor8, _assertThisInitialized(_this));
          _this.mapWeb = new Map();
          _this.mapMobile = new Map();
          _this.spriteFrames = new Map();
          return _this;
        }
        var _proto = M10SFGamer.prototype;
        _proto.onLoad = function onLoad() {
          var _this2 = this;
          var tryGetNum;
          this.orientationSprite.web_Dice.forEach(function (_spriteFrame) {
            tryGetNum = Number(_spriteFrame.name.replace("Dice_", ""));
            if (isNaN(tryGetNum)) throw new Error(_spriteFrame + ", \"\u547D\u540D\u6709\u554F\u984C\"");
            _this2.mapWeb.set(tryGetNum, _spriteFrame);
          });
          this.orientationSprite.mobile_Dice.forEach(function (_spriteFrame) {
            tryGetNum = Number(_spriteFrame.name.replace("Dice_", ""));
            if (isNaN(tryGetNum)) throw new Error(_spriteFrame + ", \"\u547D\u540D\u6709\u554F\u984C\"");
            _this2.mapMobile.set(tryGetNum, _spriteFrame);
          });
          _BaseComponent.prototype.onLoad.call(this);
        };
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          this.spriteFrames = isLandscape ? this.mapWeb : this.mapMobile;
        };
        return M10SFGamer;
      }(BaseComponent), (_descriptor7 = _applyDecoratedDescriptor(_class5.prototype, "identity", [_dec9], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return IdentityType.Player;
        }
      }), _descriptor8 = _applyDecoratedDescriptor(_class5.prototype, "orientationSprite", [_dec10], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SFGamer();
        }
      })), _class5)) || _class4));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/M10SFSelect.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BasicEnum.ts', './BasicSFPlaySelect.ts', './BasicSPButton.ts', './BasicPlaySelect.ts', './SpriteButton.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Platform, SFPlaySelect, BasicSPButton, BasicPlaySelect, SpriteButton;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
    }, function (module) {
      Platform = module.Platform;
    }, function (module) {
      SFPlaySelect = module.SFPlaySelect;
    }, function (module) {
      BasicSPButton = module.BasicSPButton;
    }, function (module) {
      BasicPlaySelect = module.default;
    }, function (module) {
      SpriteButton = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _dec5, _dec6, _dec7, _dec8, _dec9, _dec10, _dec11, _dec12, _dec13, _class, _class2, _descriptor, _descriptor2, _descriptor3, _descriptor4, _descriptor5, _descriptor6, _descriptor7, _descriptor8, _descriptor9, _descriptor10, _descriptor11, _descriptor12, _dec14, _dec15, _dec16, _dec17, _dec18, _dec19, _dec20, _dec21, _class4, _class5, _descriptor13, _descriptor14, _descriptor15, _descriptor16, _descriptor17, _descriptor18, _descriptor19;
      cclegacy._RF.push({}, "5faf0bvBiBK45+t3yjQWUHN", "M10SFSelect", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var SFSelect = (_dec = ccclass("SFSelect"), _dec2 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec3 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec4 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec5 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec6 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec7 = property({
        group: {
          name: Platform.Mobile
        },
        type: BasicSPButton
      }), _dec8 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec9 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec10 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec11 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec12 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec13 = property({
        group: {
          name: Platform.Web
        },
        type: BasicSPButton
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_SFPlaySelect) {
        _inheritsLoose(SFSelect, _SFPlaySelect);
        function SFSelect() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _SFPlaySelect.call.apply(_SFPlaySelect, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "mobile_Red", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "mobile_Black", _descriptor2, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "mobile_Odd", _descriptor3, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "mobile_Even", _descriptor4, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "mobile_Big", _descriptor5, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "mobile_Small", _descriptor6, _assertThisInitialized(_this));
          //<--------------------------------平台分界線-------------------------------------->
          _initializerDefineProperty(_this, "web_Red", _descriptor7, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "web_Black", _descriptor8, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "web_Odd", _descriptor9, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "web_Even", _descriptor10, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "web_Big", _descriptor11, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "web_Small", _descriptor12, _assertThisInitialized(_this));
          return _this;
        }
        return SFSelect;
      }(SFPlaySelect), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "mobile_Red", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "mobile_Black", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor3 = _applyDecoratedDescriptor(_class2.prototype, "mobile_Odd", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor4 = _applyDecoratedDescriptor(_class2.prototype, "mobile_Even", [_dec5], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor5 = _applyDecoratedDescriptor(_class2.prototype, "mobile_Big", [_dec6], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor6 = _applyDecoratedDescriptor(_class2.prototype, "mobile_Small", [_dec7], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor7 = _applyDecoratedDescriptor(_class2.prototype, "web_Red", [_dec8], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor8 = _applyDecoratedDescriptor(_class2.prototype, "web_Black", [_dec9], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor9 = _applyDecoratedDescriptor(_class2.prototype, "web_Odd", [_dec10], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor10 = _applyDecoratedDescriptor(_class2.prototype, "web_Even", [_dec11], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor11 = _applyDecoratedDescriptor(_class2.prototype, "web_Big", [_dec12], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      }), _descriptor12 = _applyDecoratedDescriptor(_class2.prototype, "web_Small", [_dec13], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new BasicSPButton();
        }
      })), _class2)) || _class);
      var M10SFSelect = exports('default', (_dec14 = ccclass('M10SFSelect'), _dec15 = property({
        type: SpriteButton,
        tooltip: "紅注按鈕"
      }), _dec16 = property({
        type: SpriteButton,
        tooltip: "黑注按鈕"
      }), _dec17 = property({
        type: SpriteButton,
        tooltip: "單注按鈕"
      }), _dec18 = property({
        type: SpriteButton,
        tooltip: "雙注按鈕"
      }), _dec19 = property({
        type: SpriteButton,
        tooltip: "大注按鈕"
      }), _dec20 = property({
        type: SpriteButton,
        tooltip: "小注按鈕"
      }), _dec21 = property(SFSelect), _dec14(_class4 = (_class5 = /*#__PURE__*/function (_BasicPlaySelect) {
        _inheritsLoose(M10SFSelect, _BasicPlaySelect);
        function M10SFSelect() {
          var _this2;
          for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
            args[_key2] = arguments[_key2];
          }
          _this2 = _BasicPlaySelect.call.apply(_BasicPlaySelect, [this].concat(args)) || this;
          _initializerDefineProperty(_this2, "btnRed", _descriptor13, _assertThisInitialized(_this2));
          _initializerDefineProperty(_this2, "btnBlack", _descriptor14, _assertThisInitialized(_this2));
          _initializerDefineProperty(_this2, "btnOdd", _descriptor15, _assertThisInitialized(_this2));
          _initializerDefineProperty(_this2, "btnEven", _descriptor16, _assertThisInitialized(_this2));
          _initializerDefineProperty(_this2, "btnBig", _descriptor17, _assertThisInitialized(_this2));
          _initializerDefineProperty(_this2, "btnSmall", _descriptor18, _assertThisInitialized(_this2));
          _initializerDefineProperty(_this2, "orientationSprite", _descriptor19, _assertThisInitialized(_this2));
          return _this2;
        }
        var _proto = M10SFSelect.prototype;
        _proto.orientationEvent = function orientationEvent(isLandscape) {
          if (isLandscape) {
            this.btnPlay.normalSprite = this.orientationSprite.web_Play["default"];
            this.btnPlay.pressedSprite = this.orientationSprite.web_Play.press;
            this.btnPlay.disabledSprite = this.orientationSprite.web_Play.disable;
            this.btnPlay.defaultNormalSprite = this.orientationSprite.web_Play["default"];
            this.btnPlay.defaultSelectSprite = this.orientationSprite.web_Play.press;
            this.btnOdd.normalSprite = this.orientationSprite.web_Odd["default"];
            this.btnOdd.pressedSprite = this.orientationSprite.web_Odd.press;
            this.btnOdd.disabledSprite = this.orientationSprite.web_Odd.disable;
            this.btnOdd.defaultNormalSprite = this.orientationSprite.web_Odd["default"];
            this.btnOdd.defaultSelectSprite = this.orientationSprite.web_Odd.press;
            this.btnEven.normalSprite = this.orientationSprite.web_Even["default"];
            this.btnEven.pressedSprite = this.orientationSprite.web_Even.press;
            this.btnEven.disabledSprite = this.orientationSprite.web_Even.disable;
            this.btnEven.defaultNormalSprite = this.orientationSprite.web_Even["default"];
            this.btnEven.defaultSelectSprite = this.orientationSprite.web_Even.press;
            this.btnBig.normalSprite = this.orientationSprite.web_Big["default"];
            this.btnBig.pressedSprite = this.orientationSprite.web_Big.press;
            this.btnBig.disabledSprite = this.orientationSprite.web_Big.disable;
            this.btnBig.defaultNormalSprite = this.orientationSprite.web_Big["default"];
            this.btnBig.defaultSelectSprite = this.orientationSprite.web_Big.press;
            this.btnSmall.normalSprite = this.orientationSprite.web_Small["default"];
            this.btnSmall.pressedSprite = this.orientationSprite.web_Small.press;
            this.btnSmall.disabledSprite = this.orientationSprite.web_Small.disable;
            this.btnSmall.defaultNormalSprite = this.orientationSprite.web_Small["default"];
            this.btnSmall.defaultSelectSprite = this.orientationSprite.web_Small.press;
            this.btnRed.normalSprite = this.orientationSprite.web_Red["default"];
            this.btnRed.pressedSprite = this.orientationSprite.web_Red.press;
            this.btnRed.disabledSprite = this.orientationSprite.web_Red.disable;
            this.btnRed.defaultNormalSprite = this.orientationSprite.web_Red["default"];
            this.btnRed.defaultSelectSprite = this.orientationSprite.web_Red.press;
            this.btnBlack.normalSprite = this.orientationSprite.web_Black["default"];
            this.btnBlack.pressedSprite = this.orientationSprite.web_Black.press;
            this.btnBlack.disabledSprite = this.orientationSprite.web_Black.disable;
            this.btnBlack.defaultNormalSprite = this.orientationSprite.web_Black["default"];
            this.btnBlack.defaultSelectSprite = this.orientationSprite.web_Black.press;
          } else {
            this.btnPlay.normalSprite = this.orientationSprite.mobile_Play["default"];
            this.btnPlay.pressedSprite = this.orientationSprite.mobile_Play.press;
            this.btnPlay.disabledSprite = this.orientationSprite.mobile_Play.disable;
            this.btnPlay.defaultNormalSprite = this.orientationSprite.mobile_Play["default"];
            this.btnPlay.defaultSelectSprite = this.orientationSprite.mobile_Play.press;
            this.btnOdd.normalSprite = this.orientationSprite.mobile_Odd["default"];
            this.btnOdd.pressedSprite = this.orientationSprite.mobile_Odd.press;
            this.btnOdd.disabledSprite = this.orientationSprite.mobile_Odd.disable;
            this.btnOdd.defaultNormalSprite = this.orientationSprite.mobile_Odd["default"];
            this.btnOdd.defaultSelectSprite = this.orientationSprite.mobile_Odd.press;
            this.btnEven.normalSprite = this.orientationSprite.mobile_Even["default"];
            this.btnEven.pressedSprite = this.orientationSprite.mobile_Even.press;
            this.btnEven.disabledSprite = this.orientationSprite.mobile_Even.disable;
            this.btnEven.defaultNormalSprite = this.orientationSprite.mobile_Even["default"];
            this.btnEven.defaultSelectSprite = this.orientationSprite.mobile_Even.press;
            this.btnBig.normalSprite = this.orientationSprite.mobile_Big["default"];
            this.btnBig.pressedSprite = this.orientationSprite.mobile_Big.press;
            this.btnBig.disabledSprite = this.orientationSprite.mobile_Big.disable;
            this.btnBig.defaultNormalSprite = this.orientationSprite.mobile_Big["default"];
            this.btnBig.defaultSelectSprite = this.orientationSprite.mobile_Big.press;
            this.btnSmall.normalSprite = this.orientationSprite.mobile_Small["default"];
            this.btnSmall.pressedSprite = this.orientationSprite.mobile_Small.press;
            this.btnSmall.disabledSprite = this.orientationSprite.mobile_Small.disable;
            this.btnSmall.defaultNormalSprite = this.orientationSprite.mobile_Small["default"];
            this.btnSmall.defaultSelectSprite = this.orientationSprite.mobile_Small.press;
            this.btnRed.normalSprite = this.orientationSprite.mobile_Red["default"];
            this.btnRed.pressedSprite = this.orientationSprite.mobile_Red.press;
            this.btnRed.disabledSprite = this.orientationSprite.mobile_Red.disable;
            this.btnRed.defaultNormalSprite = this.orientationSprite.mobile_Red["default"];
            this.btnRed.defaultSelectSprite = this.orientationSprite.mobile_Red.press;
            this.btnBlack.normalSprite = this.orientationSprite.mobile_Black["default"];
            this.btnBlack.pressedSprite = this.orientationSprite.mobile_Black.press;
            this.btnBlack.disabledSprite = this.orientationSprite.mobile_Black.disable;
            this.btnBlack.defaultNormalSprite = this.orientationSprite.mobile_Black["default"];
            this.btnBlack.defaultSelectSprite = this.orientationSprite.mobile_Black.press;
          }
        };
        return M10SFSelect;
      }(BasicPlaySelect), (_descriptor13 = _applyDecoratedDescriptor(_class5.prototype, "btnRed", [_dec15], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor14 = _applyDecoratedDescriptor(_class5.prototype, "btnBlack", [_dec16], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor15 = _applyDecoratedDescriptor(_class5.prototype, "btnOdd", [_dec17], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor16 = _applyDecoratedDescriptor(_class5.prototype, "btnEven", [_dec18], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor17 = _applyDecoratedDescriptor(_class5.prototype, "btnBig", [_dec19], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor18 = _applyDecoratedDescriptor(_class5.prototype, "btnSmall", [_dec20], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor19 = _applyDecoratedDescriptor(_class5.prototype, "orientationSprite", [_dec21], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return new SFSelect();
        }
      })), _class5)) || _class4));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/main", ['./AutoFollow.ts', './BaseComponent.ts', './DelayTime.ts', './EasyCode.ts', './EditSpine.mjs_cjs=&original=.js', './GoogleSheet.ts', './SheetData.ts', './CocosImage.ts', './CreateFileSprite.ts', './index2.ts', './sign.ts', './sign3.ts', './produce.ts', './sign2.ts', './import.ts', './buffer_utils.ts', './check_key_type.ts', './crypto_key.ts', './epoch.ts', './invalid_key_input.ts', './is_disjoint.ts', './is_object.ts', './secs.ts', './validate_crit.ts', './asn1.ts', './base64url.ts', './check_key_length.ts', './get_sign_verify_key.ts', './is_key_like.ts', './sign4.ts', './subtle_dsa.ts', './webcrypto.ts', './errors.ts', './browser_client.ts', './base_client.ts', './index.ts', './mod2.ts', './connack.ts', './connect.ts', './disconnect.ts', './length.ts', './mod.ts', './pingreq.ts', './pingres.ts', './puback.ts', './pubcomp.ts', './publish.ts', './pubrec.ts', './pubrel.ts', './suback.ts', './subscribe.ts', './unsuback.ts', './unsubscribe.ts', './utf8.ts', './EventMng.ts', './LanguageManager.ts', './MyEditBox.ts', './MyMath.ts', './BaseSingleton.ts', './BaseSingletonComponent.ts', './IBaseSingleton.ts', './SingletonManger.ts', './StatePatten.ts', './Public.ts', './Request.ts', './RequestData.ts', './ResponseData.ts', './SetBtnEventForKeepTouching.ts', './LookTex.ts', './aes.js', './blowfish.js', './cipher-core.js', './core.js', './enc-base64.js', './enc-base64url.js', './enc-utf16.js', './evpkdf.js', './format-hex.js', './hmac.js', './index.js', './md5.js', './mode-cfb.js', './mode-ctr-gladman.js', './mode-ctr.js', './mode-ecb.js', './mode-ofb.js', './pad-ansix923.js', './pad-iso10126.js', './pad-iso97971.js', './pad-nopadding.js', './pad-zeropadding.js', './pbkdf2.js', './rabbit-legacy.js', './rabbit.js', './rc4.js', './ripemd160.js', './sha1.js', './sha224.js', './sha256.js', './sha3.js', './sha384.js', './sha512.js', './tripledes.js', './x64-core.js', './PageViewOnlyShowItemsInMaskRange.ts', './ScrollViewEvent.ts', './ScrollViewOnlyShowItemsInMaskRange.ts', './GameContorl.ts', './M10Enum.ts', './M10SFBG.ts', './M10SFBonus.ts', './M10SFGamer.ts', './M10SFSelect.ts', './RequestContorl.ts', './RequestData2.ts', './AutoView.ts', './BasicEnum.ts', './CommonValue.ts', './CustomEvent.ts', './LabelButton.ts', './BasicSFBetInfo.ts', './BasicSFPlaySelect.ts', './BasicSFRandomSelect.ts', './BasicSPButton.ts', './BasicAutoPlay.ts', './BasicRandomAutoPlay.ts', './BasicBetInfo.ts', './BasicChip.ts', './BasicGameShow.ts', './BasicVersion.ts', './BasicPlaySelect.ts', './BasicRandomSelect.ts', './BasicSelect.ts', './ScreenAdapter.ts', './SpriteButton.ts', './M10PanelAutoPlay.ts', './M10PanelBG.ts', './M10PanelBetInfo.ts', './M10PanelBetSelect.ts', './M10Bonus.ts', './M10PanelBonus.ts', './M10PanelChip.ts', './M10Dice.ts', './M10Gamer.ts', './M10PanelGameShow.ts', './M10PanelVersion.ts'], function () {
  return {
    setters: [null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null],
    execute: function () {}
  };
});

System.register("chunks:///_virtual/md5.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, Hasher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
      Hasher = module.Hasher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "9afdaJU7rZDtpHPQ7ppEQv5", "md5", undefined);

      // Constants table
      var T = [];

      // Compute constants
      for (var i = 0; i < 64; i += 1) {
        T[i] = Math.abs(Math.sin(i + 1)) * 0x100000000 | 0;
      }
      var FF = function FF(a, b, c, d, x, s, t) {
        var n = a + (b & c | ~b & d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var GG = function GG(a, b, c, d, x, s, t) {
        var n = a + (b & d | c & ~d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var HH = function HH(a, b, c, d, x, s, t) {
        var n = a + (b ^ c ^ d) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };
      var II = function II(a, b, c, d, x, s, t) {
        var n = a + (c ^ (b | ~d)) + x + t;
        return (n << s | n >>> 32 - s) + b;
      };

      /**
       * MD5 hash algorithm.
       */
      var MD5Algo = exports('MD5Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(MD5Algo, _Hasher);
        function MD5Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = MD5Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Swap endian
          for (var _i = 0; _i < 16; _i += 1) {
            // Shortcuts
            var offset_i = offset + _i;
            var M_offset_i = M[offset_i];
            _M[offset_i] = (M_offset_i << 8 | M_offset_i >>> 24) & 0x00ff00ff | (M_offset_i << 24 | M_offset_i >>> 8) & 0xff00ff00;
          }

          // Shortcuts
          var H = this._hash.words;
          var M_offset_0 = _M[offset + 0];
          var M_offset_1 = _M[offset + 1];
          var M_offset_2 = _M[offset + 2];
          var M_offset_3 = _M[offset + 3];
          var M_offset_4 = _M[offset + 4];
          var M_offset_5 = _M[offset + 5];
          var M_offset_6 = _M[offset + 6];
          var M_offset_7 = _M[offset + 7];
          var M_offset_8 = _M[offset + 8];
          var M_offset_9 = _M[offset + 9];
          var M_offset_10 = _M[offset + 10];
          var M_offset_11 = _M[offset + 11];
          var M_offset_12 = _M[offset + 12];
          var M_offset_13 = _M[offset + 13];
          var M_offset_14 = _M[offset + 14];
          var M_offset_15 = _M[offset + 15];

          // Working varialbes
          var a = H[0];
          var b = H[1];
          var c = H[2];
          var d = H[3];

          // Computation
          a = FF(a, b, c, d, M_offset_0, 7, T[0]);
          d = FF(d, a, b, c, M_offset_1, 12, T[1]);
          c = FF(c, d, a, b, M_offset_2, 17, T[2]);
          b = FF(b, c, d, a, M_offset_3, 22, T[3]);
          a = FF(a, b, c, d, M_offset_4, 7, T[4]);
          d = FF(d, a, b, c, M_offset_5, 12, T[5]);
          c = FF(c, d, a, b, M_offset_6, 17, T[6]);
          b = FF(b, c, d, a, M_offset_7, 22, T[7]);
          a = FF(a, b, c, d, M_offset_8, 7, T[8]);
          d = FF(d, a, b, c, M_offset_9, 12, T[9]);
          c = FF(c, d, a, b, M_offset_10, 17, T[10]);
          b = FF(b, c, d, a, M_offset_11, 22, T[11]);
          a = FF(a, b, c, d, M_offset_12, 7, T[12]);
          d = FF(d, a, b, c, M_offset_13, 12, T[13]);
          c = FF(c, d, a, b, M_offset_14, 17, T[14]);
          b = FF(b, c, d, a, M_offset_15, 22, T[15]);
          a = GG(a, b, c, d, M_offset_1, 5, T[16]);
          d = GG(d, a, b, c, M_offset_6, 9, T[17]);
          c = GG(c, d, a, b, M_offset_11, 14, T[18]);
          b = GG(b, c, d, a, M_offset_0, 20, T[19]);
          a = GG(a, b, c, d, M_offset_5, 5, T[20]);
          d = GG(d, a, b, c, M_offset_10, 9, T[21]);
          c = GG(c, d, a, b, M_offset_15, 14, T[22]);
          b = GG(b, c, d, a, M_offset_4, 20, T[23]);
          a = GG(a, b, c, d, M_offset_9, 5, T[24]);
          d = GG(d, a, b, c, M_offset_14, 9, T[25]);
          c = GG(c, d, a, b, M_offset_3, 14, T[26]);
          b = GG(b, c, d, a, M_offset_8, 20, T[27]);
          a = GG(a, b, c, d, M_offset_13, 5, T[28]);
          d = GG(d, a, b, c, M_offset_2, 9, T[29]);
          c = GG(c, d, a, b, M_offset_7, 14, T[30]);
          b = GG(b, c, d, a, M_offset_12, 20, T[31]);
          a = HH(a, b, c, d, M_offset_5, 4, T[32]);
          d = HH(d, a, b, c, M_offset_8, 11, T[33]);
          c = HH(c, d, a, b, M_offset_11, 16, T[34]);
          b = HH(b, c, d, a, M_offset_14, 23, T[35]);
          a = HH(a, b, c, d, M_offset_1, 4, T[36]);
          d = HH(d, a, b, c, M_offset_4, 11, T[37]);
          c = HH(c, d, a, b, M_offset_7, 16, T[38]);
          b = HH(b, c, d, a, M_offset_10, 23, T[39]);
          a = HH(a, b, c, d, M_offset_13, 4, T[40]);
          d = HH(d, a, b, c, M_offset_0, 11, T[41]);
          c = HH(c, d, a, b, M_offset_3, 16, T[42]);
          b = HH(b, c, d, a, M_offset_6, 23, T[43]);
          a = HH(a, b, c, d, M_offset_9, 4, T[44]);
          d = HH(d, a, b, c, M_offset_12, 11, T[45]);
          c = HH(c, d, a, b, M_offset_15, 16, T[46]);
          b = HH(b, c, d, a, M_offset_2, 23, T[47]);
          a = II(a, b, c, d, M_offset_0, 6, T[48]);
          d = II(d, a, b, c, M_offset_7, 10, T[49]);
          c = II(c, d, a, b, M_offset_14, 15, T[50]);
          b = II(b, c, d, a, M_offset_5, 21, T[51]);
          a = II(a, b, c, d, M_offset_12, 6, T[52]);
          d = II(d, a, b, c, M_offset_3, 10, T[53]);
          c = II(c, d, a, b, M_offset_10, 15, T[54]);
          b = II(b, c, d, a, M_offset_1, 21, T[55]);
          a = II(a, b, c, d, M_offset_8, 6, T[56]);
          d = II(d, a, b, c, M_offset_15, 10, T[57]);
          c = II(c, d, a, b, M_offset_6, 15, T[58]);
          b = II(b, c, d, a, M_offset_13, 21, T[59]);
          a = II(a, b, c, d, M_offset_4, 6, T[60]);
          d = II(d, a, b, c, M_offset_11, 10, T[61]);
          c = II(c, d, a, b, M_offset_2, 15, T[62]);
          b = II(b, c, d, a, M_offset_9, 21, T[63]);

          // Intermediate hash value
          H[0] = H[0] + a | 0;
          H[1] = H[1] + b | 0;
          H[2] = H[2] + c | 0;
          H[3] = H[3] + d | 0;
        }
        /* eslint-ensable no-param-reassign */;
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
          var nBitsTotalL = nBitsTotal;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 15] = (nBitsTotalH << 8 | nBitsTotalH >>> 24) & 0x00ff00ff | (nBitsTotalH << 24 | nBitsTotalH >>> 8) & 0xff00ff00;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = (nBitsTotalL << 8 | nBitsTotalL >>> 24) & 0x00ff00ff | (nBitsTotalL << 24 | nBitsTotalL >>> 8) & 0xff00ff00;
          data.sigBytes = (dataWords.length + 1) * 4;

          // Hash final blocks
          this._process();

          // Shortcuts
          var hash = this._hash;
          var H = hash.words;

          // Swap endian
          for (var _i2 = 0; _i2 < 4; _i2 += 1) {
            // Shortcut
            var H_i = H[_i2];
            H[_i2] = (H_i << 8 | H_i >>> 24) & 0x00ff00ff | (H_i << 24 | H_i >>> 8) & 0xff00ff00;
          }

          // Return final computed hash
          return hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return MD5Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.MD5('message');
       *     var hash = CryptoJS.MD5(wordArray);
       */
      var MD5 = exports('MD5', Hasher._createHelper(MD5Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacMD5(message, key);
       */
      var HmacMD5 = exports('HmacMD5', Hasher._createHmacHelper(MD5Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/mod.ts", ['cc', './connack.ts', './connect.ts', './disconnect.ts', './length.ts', './pingreq.ts', './pingres.ts', './puback.ts', './pubcomp.ts', './publish.ts', './pubrec.ts', './pubrel.ts', './suback.ts', './subscribe.ts', './unsuback.ts', './unsubscribe.ts'], function (exports) {
  var cclegacy, decode$2, decode$1, decode$e, decodeLength, decode$c, decode$d, decode$4, decode$7, decode$3, decode$5, decode$6, decode$9, decode$8, decode$b, decode$a;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      decode$2 = module.decode;
    }, function (module) {
      decode$1 = module.decode;
    }, function (module) {
      decode$e = module.decode;
    }, function (module) {
      decodeLength = module.decodeLength;
    }, function (module) {
      decode$c = module.decode;
    }, function (module) {
      decode$d = module.decode;
    }, function (module) {
      decode$4 = module.decode;
    }, function (module) {
      decode$7 = module.decode;
    }, function (module) {
      decode$3 = module.decode;
    }, function (module) {
      decode$5 = module.decode;
    }, function (module) {
      decode$6 = module.decode;
    }, function (module) {
      decode$9 = module.decode;
    }, function (module) {
      decode$8 = module.decode;
    }, function (module) {
      decode$b = module.decode;
    }, function (module) {
      decode$a = module.decode;
    }],
    execute: function () {
      exports('decode', decode);
      cclegacy._RF.push({}, "dd530sTf0dCd6ZBDMl7baMV", "mod", undefined);
      var packetDecoders = [null, decode$1,
      // 1
      decode$2,
      // 2
      decode$3,
      // 3
      decode$4,
      // 4
      decode$5,
      // 5
      decode$6,
      // 6
      decode$7,
      // 7
      decode$8,
      // 8
      decode$9,
      // 9
      decode$a,
      // 10
      decode$b,
      // 11
      decode$c,
      // 12
      decode$d,
      // 13
      decode$e // 14
      ];

      function decode(buffer, utf8Decoder) {
        if (buffer.length < 2) {
          return null;
        }
        var id = buffer[0] >> 4;
        var decoder = packetDecoders[id];
        if (!decoder) {
          throw new Error("packet type " + id + " cannot be decoded");
        }
        var _decodeLength = decodeLength(buffer, 1),
          remainingLength = _decodeLength.length,
          bytesUsedToEncodeLength = _decodeLength.bytesUsedToEncodeLength;
        var packetLength = 1 + bytesUsedToEncodeLength + remainingLength;
        if (buffer.length < packetLength) {
          return null;
        }
        var packet = decoder(buffer, 1 + bytesUsedToEncodeLength, remainingLength, utf8Decoder);
        if (!packet) {
          return null;
        }
        var packetWithLength = packet;
        packetWithLength.length = packetLength;
        return packetWithLength;
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/mod2.ts", ['cc'], function () {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "ff7c0MqcplBbYkCE2VPj1VN", "mod", undefined);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/mode-cfb.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      cclegacy._RF.push({}, "c6e24eRvYVDg5lJuZvB5Xqh", "mode-cfb", undefined);
      function generateKeystreamAndEncrypt(words, offset, blockSize, cipher) {
        var _words = words;
        var keystream;

        // Shortcut
        var iv = this._iv;

        // Generate keystream
        if (iv) {
          keystream = iv.slice(0);

          // Remove IV for subsequent blocks
          this._iv = undefined;
        } else {
          keystream = this._prevBlock;
        }
        cipher.encryptBlock(keystream, 0);

        // Encrypt
        for (var i = 0; i < blockSize; i += 1) {
          _words[offset + i] ^= keystream[i];
        }
      }

      /**
       * Cipher Feedback block mode.
       */
      var CFB = exports('CFB', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CFB, _BlockCipherMode);
        function CFB() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CFB;
      }(BlockCipherMode));
      CFB.Encryptor = /*#__PURE__*/function (_CFB) {
        _inheritsLoose(_class, _CFB);
        function _class() {
          return _CFB.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

          // Remember this block to use with next block
          this._prevBlock = words.slice(offset, offset + blockSize);
        };
        return _class;
      }(CFB);
      CFB.Decryptor = /*#__PURE__*/function (_CFB2) {
        _inheritsLoose(_class2, _CFB2);
        function _class2() {
          return _CFB2.apply(this, arguments) || this;
        }
        var _proto2 = _class2.prototype;
        _proto2.processBlock = function processBlock(words, offset) {
          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;

          // Remember this block to use with next block
          var thisBlock = words.slice(offset, offset + blockSize);
          generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

          // This block becomes the previous block
          this._prevBlock = thisBlock;
        };
        return _class2;
      }(CFB);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/mode-ctr-gladman.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      cclegacy._RF.push({}, "36852cHSk9PE6Z2VzEoAuqz", "mode-ctr-gladman", undefined);
      var incWord = function incWord(word) {
        var _word = word;
        if ((word >> 24 & 0xff) === 0xff) {
          // overflow
          var b1 = word >> 16 & 0xff;
          var b2 = word >> 8 & 0xff;
          var b3 = word & 0xff;
          if (b1 === 0xff) {
            // overflow b1
            b1 = 0;
            if (b2 === 0xff) {
              b2 = 0;
              if (b3 === 0xff) {
                b3 = 0;
              } else {
                b3 += 1;
              }
            } else {
              b2 += 1;
            }
          } else {
            b1 += 1;
          }
          _word = 0;
          _word += b1 << 16;
          _word += b2 << 8;
          _word += b3;
        } else {
          _word += 0x01 << 24;
        }
        return _word;
      };
      var incCounter = function incCounter(counter) {
        var _counter = counter;
        _counter[0] = incWord(_counter[0]);
        if (_counter[0] === 0) {
          // encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
          _counter[1] = incWord(_counter[1]);
        }
        return _counter;
      };

      /** @preserve
       * Counter block mode compatible with  Dr Brian Gladman fileenc.c
       * derived from CryptoJS.mode.CTR
       * Jan Hruby jhruby.web@gmail.com
       */
      var CTRGladman = exports('CTRGladman', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CTRGladman, _BlockCipherMode);
        function CTRGladman() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CTRGladman;
      }(BlockCipherMode));
      CTRGladman.Encryptor = /*#__PURE__*/function (_CTRGladman) {
        _inheritsLoose(_class, _CTRGladman);
        function _class() {
          return _CTRGladman.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          var _words = words;

          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          var iv = this._iv;
          var counter = this._counter;

          // Generate keystream
          if (iv) {
            this._counter = iv.slice(0);
            counter = this._counter;

            // Remove IV for subsequent blocks
            this._iv = undefined;
          }
          incCounter(counter);
          var keystream = counter.slice(0);
          cipher.encryptBlock(keystream, 0);

          // Encrypt
          for (var i = 0; i < blockSize; i += 1) {
            _words[offset + i] ^= keystream[i];
          }
        };
        return _class;
      }(CTRGladman);
      CTRGladman.Decryptor = CTRGladman.Encryptor;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/mode-ctr.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      cclegacy._RF.push({}, "30218ctcvtAoYsDQiZw/JZ8", "mode-ctr", undefined);

      /**
       * Counter block mode.
       */
      var CTR = exports('CTR', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(CTR, _BlockCipherMode);
        function CTR() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return CTR;
      }(BlockCipherMode));
      CTR.Encryptor = /*#__PURE__*/function (_CTR) {
        _inheritsLoose(_class, _CTR);
        function _class() {
          return _CTR.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          var _words = words;

          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          var iv = this._iv;
          var counter = this._counter;

          // Generate keystream
          if (iv) {
            this._counter = iv.slice(0);
            counter = this._counter;

            // Remove IV for subsequent blocks
            this._iv = undefined;
          }
          var keystream = counter.slice(0);
          cipher.encryptBlock(keystream, 0);

          // Increment counter
          counter[blockSize - 1] = counter[blockSize - 1] + 1 | 0;

          // Encrypt
          for (var i = 0; i < blockSize; i += 1) {
            _words[offset + i] ^= keystream[i];
          }
        };
        return _class;
      }(CTR);
      CTR.Decryptor = CTR.Encryptor;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/mode-ecb.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      cclegacy._RF.push({}, "6d92dMyPW9PBbzOMoBGvyFp", "mode-ecb", undefined);

      /**
       * Electronic Codebook block mode.
       */
      var ECB = exports('ECB', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(ECB, _BlockCipherMode);
        function ECB() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return ECB;
      }(BlockCipherMode));
      ECB.Encryptor = /*#__PURE__*/function (_ECB) {
        _inheritsLoose(_class, _ECB);
        function _class() {
          return _ECB.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          this._cipher.encryptBlock(words, offset);
        };
        return _class;
      }(ECB);
      ECB.Decryptor = /*#__PURE__*/function (_ECB2) {
        _inheritsLoose(_class2, _ECB2);
        function _class2() {
          return _ECB2.apply(this, arguments) || this;
        }
        var _proto2 = _class2.prototype;
        _proto2.processBlock = function processBlock(words, offset) {
          this._cipher.decryptBlock(words, offset);
        };
        return _class2;
      }(ECB);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/mode-ofb.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, BlockCipherMode;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BlockCipherMode = module.BlockCipherMode;
    }],
    execute: function () {
      cclegacy._RF.push({}, "6ff95tShsNB450EqgYDQ3kC", "mode-ofb", undefined);

      /**
       * Output Feedback block mode.
       */
      var OFB = exports('OFB', /*#__PURE__*/function (_BlockCipherMode) {
        _inheritsLoose(OFB, _BlockCipherMode);
        function OFB() {
          return _BlockCipherMode.apply(this, arguments) || this;
        }
        return OFB;
      }(BlockCipherMode));
      OFB.Encryptor = /*#__PURE__*/function (_OFB) {
        _inheritsLoose(_class, _OFB);
        function _class() {
          return _OFB.apply(this, arguments) || this;
        }
        var _proto = _class.prototype;
        _proto.processBlock = function processBlock(words, offset) {
          var _words = words;

          // Shortcuts
          var cipher = this._cipher;
          var blockSize = cipher.blockSize;
          var iv = this._iv;
          var keystream = this._keystream;

          // Generate keystream
          if (iv) {
            this._keystream = iv.slice(0);
            keystream = this._keystream;

            // Remove IV for subsequent blocks
            this._iv = undefined;
          }
          cipher.encryptBlock(keystream, 0);

          // Encrypt
          for (var i = 0; i < blockSize; i += 1) {
            _words[offset + i] ^= keystream[i];
          }
        };
        return _class;
      }(OFB);
      OFB.Decryptor = OFB.Encryptor;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/MyEditBox.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, Sprite, Node, Label, EditBox;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Sprite = module.Sprite;
      Node = module.Node;
      Label = module.Label;
      EditBox = module.EditBox;
    }],
    execute: function () {
      var _dec, _dec2, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "00c6at5wGtKUJTZTQiqucUU", "MyEditBox", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var LEFT_PADDING = 2;
      var MyEditBox = exports('MyEditBox', (_dec = ccclass('MyEditBox'), _dec2 = property(Sprite), _dec(_class = (_class2 = /*#__PURE__*/function (_EditBox) {
        _inheritsLoose(MyEditBox, _EditBox);
        function MyEditBox() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _EditBox.call.apply(_EditBox, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "spriteBG", _descriptor, _assertThisInitialized(_this));
          _initializerDefineProperty(_this, "isAutoOff", _descriptor2, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = MyEditBox.prototype;
        _proto._updateLabelPosition = function _updateLabelPosition(size) {
          if (!this.isAutoOff) return;
          var trans = this.node._uiProps.uiTransformComp;
          var offX = -trans.anchorX * trans.width;
          var offY = -trans.anchorY * trans.height;
          var placeholderLabel = this._placeholderLabel;
          var textLabel = this._textLabel;
          if (textLabel) {
            textLabel.node._uiProps.uiTransformComp.setContentSize(size.width - LEFT_PADDING, size.height);
            textLabel.node.setPosition(offX + LEFT_PADDING, offY + size.height, textLabel.node.position.z);
            if (this._inputMode === 0) ;
            // textLabel.enableWrapText = this._inputMode === InputMode.ANY;
            textLabel.enableWrapText = this._inputMode === 0;
          }
          if (placeholderLabel) {
            placeholderLabel.node._uiProps.uiTransformComp.setContentSize(size.width - LEFT_PADDING, size.height);
            placeholderLabel.lineHeight = size.height;
            placeholderLabel.node.setPosition(offX + LEFT_PADDING, offY + size.height, placeholderLabel.node.position.z);
            // placeholderLabel.enableWrapText = this._inputMode === InputMode.ANY;
            placeholderLabel.enableWrapText = this._inputMode === 0;
          }
        };
        _proto._updateTextLabel = function _updateTextLabel() {
          var textLabel = this._textLabel; // If textLabel doesn't exist, create one.

          if (!textLabel) {
            var node = this.node.getChildByName('TEXT_LABEL');
            if (!node) {
              node = new Node('TEXT_LABEL');
              node.layer = this.node.layer;
            }
            textLabel = node.getComponent(Label);
            if (!textLabel) {
              textLabel = node.addComponent(Label);
            }
            textLabel.overflow = Label.Overflow.CLAMP;
            node.parent = this.node;
            this._textLabel = textLabel;
          } // update

          // const transformComp = this._textLabel.node._uiProps.uiTransformComp;
          // transformComp.setAnchorPoint(0, 1);

          if (this._inputMode === 0) {
            //   textLabel.verticalAlign = VerticalTextAlignment.TOP;
            textLabel.enableWrapText = true;
          } else {
            textLabel.enableWrapText = false;
          }
          textLabel.string = this._updateLabelStringStyle(this._string);
        };
        _proto._updatePlaceholderLabel = function _updatePlaceholderLabel() {
          var placeholderLabel = this._placeholderLabel; // If placeholderLabel doesn't exist, create one.

          if (!placeholderLabel) {
            var node = this.node.getChildByName('PLACEHOLDER_LABEL');
            if (!node) {
              node = new Node('PLACEHOLDER_LABEL');
              node.layer = this.node.layer;
            }
            placeholderLabel = node.getComponent(Label);
            if (!placeholderLabel) {
              placeholderLabel = node.addComponent(Label);
            }
            placeholderLabel.overflow = Label.Overflow.CLAMP;
            node.parent = this.node;
            this._placeholderLabel = placeholderLabel;
          } // update

          // const transform = this._placeholderLabel.node._uiProps.uiTransformComp;
          // transform.setAnchorPoint(0, 1);

          if (this._inputMode === 0) {
            // placeholderLabel.verticalAlign = VerticalTextAlignment.TOP;
            placeholderLabel.enableWrapText = true;
          } else {
            placeholderLabel.enableWrapText = false;
          }
          placeholderLabel.string = this.placeholder;
        };
        return MyEditBox;
      }(EditBox), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "spriteBG", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "isAutoOff", [property], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return true;
        }
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/MyMath.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "20f81sRbwZLkobF0d1gZZfb", "MyMath", undefined);
      var MyMath = exports('default', /*#__PURE__*/function () {
        function MyMath() {}
        var _proto = MyMath.prototype;
        /**
        * 加法
        */
        _proto.add = function add(value1, value2, lenght) {
          return Math.round(value1 * 1000 + value2 * 1000) / 1000;
        }
        /**
        * 減法
        */;
        _proto.minus = function minus(value1, value2, lenght) {
          return (value1 * 1000 - value2 * 1000) / 1000;
        }
        /**
        * 乘法
        */;
        _proto.multiply = function multiply(value1, value2, lenght) {
          return Math.round(value1 * 1000 * (value2 * 1000)) / Math.pow(1000, 2);
        }
        /**
        * 除法
        */;
        _proto.divide = function divide(value1, value2, lenght) {
          return value1 * 1000 / (value2 * 1000);
        }
        /**
         * 四捨五入法
         * @param value 
         * @param length 
         * @returns 
         */;
        _proto.round = function round(value, length) {
          if (length === void 0) {
            length = 4;
          }
          var val = value;
          var split = val.toString().split('.');
          if (split.length > 1 && split[1].length > length) {
            return Number(val.toPrecision(split[0].length + length));
          } else return value;
        };
        _proto.formatAdd00 = function formatAdd00(val) {
          if (typeof val != "string") val = val.toString();
          var getPoint = val.split('.');
          var addNum = "";
          if (getPoint.length > 1)
            //代表有小數點
            {
              var getlen = getPoint[1].length;
              if (getlen == 1) {
                // random = Math.floor(Math.random() * 10);
                addNum = "0";
                return val + addNum;
              } else return val;
            } else {
            //沒有小數點
            // random = Math.floor(Math.random() * 100);
            addNum = ".00";
            return val + addNum;
          }
        };
        return MyMath;
      }());
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pad-ansix923.js", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "4fdf2HoSAxI9YzIntdwbpCw", "pad-ansix923", undefined);
      /**
       * ANSI X.923 padding strategy.
       */
      var AnsiX923 = exports('AnsiX923', {
        pad: function pad(data, blockSize) {
          var _data = data;

          // Shortcuts
          var dataSigBytes = _data.sigBytes;
          var blockSizeBytes = blockSize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes;

          // Compute last byte position
          var lastBytePos = dataSigBytes + nPaddingBytes - 1;

          // Pad
          _data.clamp();
          _data.words[lastBytePos >>> 2] |= nPaddingBytes << 24 - lastBytePos % 4 * 8;
          _data.sigBytes += nPaddingBytes;
        },
        unpad: function unpad(data) {
          var _data = data;

          // Get number of padding bytes from last byte
          var nPaddingBytes = _data.words[_data.sigBytes - 1 >>> 2] & 0xff;

          // Remove padding
          _data.sigBytes -= nPaddingBytes;
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pad-iso10126.js", ['cc', './core.js'], function (exports) {
  var cclegacy, WordArray;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
    }],
    execute: function () {
      cclegacy._RF.push({}, "8eb60uiGIlCAqW1cH0iarjf", "pad-iso10126", undefined);

      /**
       * ISO 10126 padding strategy.
       */
      var Iso10126 = exports('Iso10126', {
        pad: function pad(data, blockSize) {
          // Shortcut
          var blockSizeBytes = blockSize * 4;

          // Count padding bytes
          var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

          // Pad
          data.concat(WordArray.random(nPaddingBytes - 1)).concat(WordArray.create([nPaddingBytes << 24], 1));
        },
        unpad: function unpad(data) {
          var _data = data;
          // Get number of padding bytes from last byte
          var nPaddingBytes = _data.words[_data.sigBytes - 1 >>> 2] & 0xff;

          // Remove padding
          _data.sigBytes -= nPaddingBytes;
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pad-iso97971.js", ['cc', './core.js', './pad-zeropadding.js'], function (exports) {
  var cclegacy, WordArray, ZeroPadding;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
    }, function (module) {
      ZeroPadding = module.ZeroPadding;
    }],
    execute: function () {
      cclegacy._RF.push({}, "dc9e5UJSctAu4UmZ4sBuTUJ", "pad-iso97971", undefined);

      /**
       * ISO/IEC 9797-1 Padding Method 2.
       */
      var Iso97971 = exports('Iso97971', {
        pad: function pad(data, blockSize) {
          // Add 0x80 byte
          data.concat(WordArray.create([0x80000000], 1));

          // Zero pad the rest
          ZeroPadding.pad(data, blockSize);
        },
        unpad: function unpad(data) {
          var _data = data;

          // Remove zero padding
          ZeroPadding.unpad(_data);

          // Remove one more byte -- the 0x80 byte
          _data.sigBytes -= 1;
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pad-nopadding.js", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "2f6680/A91KUIRnPSBP5prz", "pad-nopadding", undefined);
      /**
       * A noop padding strategy.
       */
      var NoPadding = exports('NoPadding', {
        pad: function pad() {},
        unpad: function unpad() {}
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pad-zeropadding.js", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "af53f2uH15PwYD+JCQ++1f/", "pad-zeropadding", undefined);
      /**
       * Zero padding strategy.
       */
      var ZeroPadding = exports('ZeroPadding', {
        pad: function pad(data, blockSize) {
          var _data = data;

          // Shortcut
          var blockSizeBytes = blockSize * 4;

          // Pad
          _data.clamp();
          _data.sigBytes += blockSizeBytes - (data.sigBytes % blockSizeBytes || blockSizeBytes);
        },
        unpad: function unpad(data) {
          var _data = data;

          // Shortcut
          var dataWords = _data.words;

          // Unpad
          for (var i = _data.sigBytes - 1; i >= 0; i -= 1) {
            if (dataWords[i >>> 2] >>> 24 - i % 4 * 8 & 0xff) {
              _data.sigBytes = i + 1;
              break;
            }
          }
        }
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/PageViewOnlyShowItemsInMaskRange.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './AutoFollow.ts', './EventMng.ts', './ScrollViewEvent.ts'], function () {
  var _inheritsLoose, cclegacy, _decorator, find, Layout, Mask, UITransform, Sprite, Label, PageView, TheTarget, EventMng, NotificationType, ScrollViewEvent;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      find = module.find;
      Layout = module.Layout;
      Mask = module.Mask;
      UITransform = module.UITransform;
      Sprite = module.Sprite;
      Label = module.Label;
      PageView = module.PageView;
    }, function (module) {
      TheTarget = module.TheTarget;
    }, function (module) {
      EventMng = module.default;
      NotificationType = module.NotificationType;
    }, function (module) {
      ScrollViewEvent = module.ScrollViewEvent;
    }],
    execute: function () {
      var _dec, _dec2, _class;
      cclegacy._RF.push({}, "743e9OKvAtOlbl6WmhxUmP7", "PageViewOnlyShowItemsInMaskRange", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property,
        menu = _decorator.menu;
      var PageViewOnlyShowItemsInMaskRange = (_dec = ccclass('PageViewOnlyShowItemsInMaskRange'), _dec2 = menu('PageViewOnlyShowItemsInMaskRange'), _dec(_class = _dec2(_class = /*#__PURE__*/function (_PageView) {
        _inheritsLoose(PageViewOnlyShowItemsInMaskRange, _PageView);
        function PageViewOnlyShowItemsInMaskRange() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _PageView.call.apply(_PageView, [this].concat(args)) || this;
          _this.minX = void 0;
          _this.maxX = void 0;
          _this.minY = void 0;
          _this.maxY = void 0;
          _this.mask = void 0;
          _this.targets = [];
          _this.sprites = [];
          _this.labels = [];
          _this.layout = void 0;
          _this.spriteTran = [];
          _this.labelTran = [];
          _this.targetTran = [];
          return _this;
        }
        var _proto = PageViewOnlyShowItemsInMaskRange.prototype;
        _proto.onLoad = function onLoad() {
          _PageView.prototype.onLoad.call(this);
          EventMng.getInstance.setEvent(NotificationType.ScrollView, ScrollViewEvent.setShowRange, this.setShowRange, this);
          EventMng.getInstance.setEvent(NotificationType.ScrollView, ScrollViewEvent.checkItemVisible, this.refreshItemCompent, this);
          this.mask = find("Mask", this.node);
          this.layout = this.content.getComponent(Layout);
        };
        _proto.start = function start() {
          _PageView.prototype.start.call(this);
          this.setShowRange();
          this.refreshItemCompent();
        };
        _proto.setShowRange = function setShowRange() {
          var viewNode = this.node;
          if (this.mask) viewNode = this.node.getComponentInChildren(Mask).node;
          var uiTransform = viewNode.getComponent(UITransform);
          this.minX = viewNode.getWorldPosition().x - 100 - uiTransform.contentSize.width * uiTransform.anchorPoint.x;
          this.maxX = viewNode.getWorldPosition().x + 100 + uiTransform.contentSize.width * (1 - uiTransform.anchorPoint.x);
          this.minY = viewNode.getWorldPosition().y - 100 - uiTransform.contentSize.height * uiTransform.anchorPoint.y;
          this.maxY = viewNode.getWorldPosition().y + 100 + uiTransform.contentSize.height * (1 - uiTransform.anchorPoint.y);
          // warn(this.node.parent.name, this.minX, this.maxX, this.minY, this.maxY)
        };

        _proto.checkItemVisible = function checkItemVisible() {
          this.layout.updateLayout();
          for (var i = 0; i < this.content.children.length; i++) {
            if (this.horizontal) {
              if (this.sprites[i]) for (var j = 0; j < this.sprites[i].length; j++) {
                if (!this.sprites[i][j].node) continue;
                var width = this.spriteTran[j].width;
                var anchorX = this.spriteTran[j].anchorX;
                var posL = this.sprites[i][j].node.getWorldPosition().x - width * anchorX;
                var posR = this.sprites[i][j].node.getWorldPosition().x + width * (1 - anchorX);
                if (posR >= this.minX && posL <= this.maxX) this.sprites[i][j].enabled = true;else this.sprites[i][j].enabled = false;
              }
              if (this.labels[i]) for (var _j = 0; _j < this.labels[i].length; _j++) {
                if (!this.labels[i][_j].node) continue;
                var _width = this.labelTran[_j].width;
                var _anchorX = this.labelTran[_j].anchorX;
                var _posL = this.labels[i][_j].node.getWorldPosition().x - _width * _anchorX;
                var _posR = this.labels[i][_j].node.getWorldPosition().x + _width * (1 - _anchorX);
                if (_posR >= this.minX && _posL <= this.maxX) this.labels[i][_j].enabled = true;else this.labels[i][_j].enabled = false;
              }
              if (this.targets[i]) for (var _j2 = 0; _j2 < this.targets[i].length; _j2++) {
                if (!this.targets[i][_j2].node) continue;
                var _width2 = this.targetTran[_j2].width;
                var _anchorX2 = this.targetTran[_j2].anchorX;
                var _posL2 = this.targets[i][_j2].node.getWorldPosition().x - _width2 * _anchorX2;
                var _posR2 = this.targets[i][_j2].node.getWorldPosition().x + _width2 * (1 - _anchorX2);
                if (_posR2 >= this.minX && _posL2 <= this.maxX) this.targets[i][_j2].isCanSee = true;else this.targets[i][_j2].isCanSee = false;
              }
            } else {
              if (this.sprites[i]) for (var _j3 = 0; _j3 < this.sprites[i].length; _j3++) {
                if (!this.sprites[i][_j3].node) continue;
                var height = this.spriteTran[_j3].height;
                var anchorY = this.spriteTran[_j3].anchorY;
                var posB = this.sprites[i][_j3].node.getWorldPosition().y - height * anchorY;
                var posT = this.sprites[i][_j3].node.getWorldPosition().y + height * (1 - anchorY);
                if (posT >= this.minY && posB <= this.maxY) this.sprites[i][_j3].enabled = true;else this.sprites[i][_j3].enabled = false;
              }
              if (this.labels[i]) for (var _j4 = 0; _j4 < this.labels[i].length; _j4++) {
                if (!this.labels[i][_j4].node) continue;
                var _height = this.labelTran[_j4].height;
                var _anchorY = this.labelTran[_j4].anchorY;
                var _posB = this.labels[i][_j4].node.getWorldPosition().y - _height * _anchorY;
                var _posT = this.labels[i][_j4].node.getWorldPosition().y + _height * (1 - _anchorY);
                if (_posT >= this.minY && _posB <= this.maxY) this.labels[i][_j4].enabled = true;else this.labels[i][_j4].enabled = false;
              }
              if (this.targets[i]) for (var _j5 = 0; _j5 < this.targets[i].length; _j5++) {
                if (!this.targets[i][_j5].node) continue;
                var _height2 = this.targetTran[_j5].height;
                var _anchorY2 = this.targetTran[_j5].anchorY;
                var _posB2 = this.targets[i][_j5].node.getWorldPosition().y - _height2 * _anchorY2;
                var _posT2 = this.targets[i][_j5].node.getWorldPosition().y + _height2 * (1 - _anchorY2);
                if (_posT2 >= this.minY && _posB2 <= this.maxY) this.targets[i][_j5].isCanSee = true;else this.targets[i][_j5].isCanSee = false;
              }
            }
          }
          // EventMng.getInstance.emit(NotificationType.Pulic, GameEvent.resetDynamicAtlas)
        };

        _proto.update = function update(dt) {
          var _this2 = this;
          _PageView.prototype.update.call(this, dt);
          var pos0 = this.content.getPosition();
          this.scheduleOnce(function () {
            if (_this2.content && (pos0.x != _this2.content.getPosition().x || pos0.y != _this2.content.getPosition().y)) _this2.checkItemVisible();
          }, 0);
        };
        _proto.onDestroy = function onDestroy() {
          EventMng.getInstance.deletEvent(NotificationType.ScrollView, ScrollViewEvent.setShowRange, this.setShowRange, this);
          EventMng.getInstance.deletEvent(NotificationType.ScrollView, ScrollViewEvent.checkItemVisible, this.refreshItemCompent, this);
        };
        _proto.refreshItemCompent = function refreshItemCompent() {
          this.targets = [];
          this.sprites = [];
          this.labels = [];
          this.targetTran = [];
          this.spriteTran = [];
          this.labelTran = [];
          for (var i = 0; i < this.content.children.length; i++) {
            this.targets.push(this.content.children[i].getComponentsInChildren(TheTarget));
            this.sprites.push(this.content.children[i].getComponentsInChildren(Sprite));
            this.labels.push(this.content.children[i].getComponentsInChildren(Label));
            for (var j = 0; j < this.targets[i].length; j++) {
              this.targetTran.push(this.targets[i][j].node.getComponent(UITransform));
            }
            for (var _j6 = 0; _j6 < this.sprites[i].length; _j6++) {
              this.spriteTran.push(this.sprites[i][_j6].node.getComponent(UITransform));
            }
            for (var _j7 = 0; _j7 < this.labels[i].length; _j7++) {
              this.labelTran.push(this.labels[i][_j7].node.getComponent(UITransform));
            }
          }
          this.checkItemVisible();
        };
        return PageViewOnlyShowItemsInMaskRange;
      }(PageView)) || _class) || _class);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pbkdf2.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js', './sha1.js', './hmac.js'], function (exports) {
  var _inheritsLoose, cclegacy, HMAC, WordArray, Base, SHA1Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      HMAC = module.HMAC;
      WordArray = module.WordArray;
      Base = module.Base;
    }, function (module) {
      SHA1Algo = module.SHA1Algo;
    }, null],
    execute: function () {
      cclegacy._RF.push({}, "d0b54w3/GVNDJsmxrwVwsv+", "pbkdf2", undefined);

      /**
       * Password-Based Key Derivation Function 2 algorithm.
       */
      var PBKDF2Algo = exports('PBKDF2Algo', /*#__PURE__*/function (_Base) {
        _inheritsLoose(PBKDF2Algo, _Base);
        /**
         * Initializes a newly created key derivation function.
         *
         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
         *
         * @example
         *
         *     const kdf = CryptoJS.algo.PBKDF2.create();
         *     const kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
         *     const kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
         */
        function PBKDF2Algo(cfg) {
          var _this;
          _this = _Base.call(this) || this;

          /**
           * Configuration options.
           *
           * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
           * @property {Hasher} hasher The hasher to use. Default: SHA1
           * @property {number} iterations The number of iterations to perform. Default: 1
           */
          _this.cfg = Object.assign(new Base(), {
            keySize: 128 / 32,
            hasher: SHA1Algo,
            iterations: 1
          }, cfg);
          return _this;
        }

        /**
         * Computes the Password-Based Key Derivation Function 2.
         *
         * @param {WordArray|string} password The password.
         * @param {WordArray|string} salt A salt.
         *
         * @return {WordArray} The derived key.
         *
         * @example
         *
         *     const key = kdf.compute(password, salt);
         */
        var _proto = PBKDF2Algo.prototype;
        _proto.compute = function compute(password, salt) {
          // Shortcut
          var cfg = this.cfg;

          // Init HMAC
          var hmac = HMAC.create(cfg.hasher, password);

          // Initial values
          var derivedKey = WordArray.create();
          var blockIndex = WordArray.create([0x00000001]);

          // Shortcuts
          var derivedKeyWords = derivedKey.words;
          var blockIndexWords = blockIndex.words;
          var keySize = cfg.keySize,
            iterations = cfg.iterations;

          // Generate key
          while (derivedKeyWords.length < keySize) {
            var block = hmac.update(salt).finalize(blockIndex);
            hmac.reset();

            // Shortcuts
            var blockWords = block.words;
            var blockWordsLength = blockWords.length;

            // Iterations
            var intermediate = block;
            for (var i = 1; i < iterations; i += 1) {
              intermediate = hmac.finalize(intermediate);
              hmac.reset();

              // Shortcut
              var intermediateWords = intermediate.words;

              // XOR intermediate with block
              for (var j = 0; j < blockWordsLength; j += 1) {
                blockWords[j] ^= intermediateWords[j];
              }
            }
            derivedKey.concat(block);
            blockIndexWords[0] += 1;
          }
          derivedKey.sigBytes = keySize * 4;
          return derivedKey;
        };
        return PBKDF2Algo;
      }(Base));

      /**
       * Computes the Password-Based Key Derivation Function 2.
       *
       * @param {WordArray|string} password The password.
       * @param {WordArray|string} salt A salt.
       * @param {Object} cfg (Optional) The configuration options to use for this computation.
       *
       * @return {WordArray} The derived key.
       *
       * @static
       *
       * @example
       *
       *     var key = CryptoJS.PBKDF2(password, salt);
       *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
       *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
       */
      var PBKDF2 = exports('PBKDF2', function PBKDF2(password, salt, cfg) {
        return PBKDF2Algo.create(cfg).compute(password, salt);
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pingreq.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "01a6bIi/yxG447dPnNqooRB", "pingreq", undefined);
      function encode(_packet) {
        var packetType = 12;
        var flags = 0;
        return Uint8Array.from([(packetType << 4) + flags, 0]);
      }
      function decode(_buffer, _remainingStart, _remainingLength) {
        return {
          type: "pingreq"
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pingres.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "eeaf0UgW3FDWLvPGP6cXRgL", "pingres", undefined);
      function encode(_packet) {
        return Uint8Array.from([0xd0, 0]);
      }
      function decode(_buffer, _remainingStart, _remainingLength) {
        return {
          type: "pingres"
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/produce.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './epoch.ts', './is_object.ts', './secs.ts'], function (exports) {
  var _extends, cclegacy, epoch, isObject, secs;
  return {
    setters: [function (module) {
      _extends = module.extends;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      epoch = module.default;
    }, function (module) {
      isObject = module.default;
    }, function (module) {
      secs = module.default;
    }],
    execute: function () {
      cclegacy._RF.push({}, "bedb9LBwXRFDY6NLjcoc2KX", "produce", undefined);
      function validateInput(label, input) {
        if (!Number.isFinite(input)) {
          throw new TypeError("Invalid " + label + " input");
        }
        return input;
      }

      /** Generic class for JWT producing. */
      var ProduceJWT = exports('ProduceJWT', /*#__PURE__*/function () {
        /** @param payload The JWT Claims Set object. Defaults to an empty object. */
        function ProduceJWT(payload) {
          if (payload === void 0) {
            payload = {};
          }
          this._payload = void 0;
          if (!isObject(payload)) {
            throw new TypeError('JWT Claims Set MUST be an object');
          }
          this._payload = payload;
        }

        /**
         * Set the "iss" (Issuer) Claim.
         *
         * @param issuer "Issuer" Claim value to set on the JWT Claims Set.
         */
        var _proto = ProduceJWT.prototype;
        _proto.setIssuer = function setIssuer(issuer) {
          this._payload = _extends({}, this._payload, {
            iss: issuer
          });
          return this;
        }

        /**
         * Set the "sub" (Subject) Claim.
         *
         * @param subject "sub" (Subject) Claim value to set on the JWT Claims Set.
         */;
        _proto.setSubject = function setSubject(subject) {
          this._payload = _extends({}, this._payload, {
            sub: subject
          });
          return this;
        }

        /**
         * Set the "aud" (Audience) Claim.
         *
         * @param audience "aud" (Audience) Claim value to set on the JWT Claims Set.
         */;
        _proto.setAudience = function setAudience(audience) {
          this._payload = _extends({}, this._payload, {
            aud: audience
          });
          return this;
        }

        /**
         * Set the "jti" (JWT ID) Claim.
         *
         * @param jwtId "jti" (JWT ID) Claim value to set on the JWT Claims Set.
         */;
        _proto.setJti = function setJti(jwtId) {
          this._payload = _extends({}, this._payload, {
            jti: jwtId
          });
          return this;
        }

        /**
         * Set the "nbf" (Not Before) Claim.
         *
         * - If a `number` is passed as an argument it is used as the claim directly.
         * - If a `Date` instance is passed as an argument it is converted to unix timestamp and used as the
         *   claim.
         * - If a `string` is passed as an argument it is resolved to a time span, and then added to the
         *   current unix timestamp and used as the claim.
         *
         * Format used for time span should be a number followed by a unit, such as "5 minutes" or "1
         * day".
         *
         * Valid units are: "sec", "secs", "second", "seconds", "s", "minute", "minutes", "min", "mins",
         * "m", "hour", "hours", "hr", "hrs", "h", "day", "days", "d", "week", "weeks", "w", "year",
         * "years", "yr", "yrs", and "y". It is not possible to specify months. 365.25 days is used as an
         * alias for a year.
         *
         * If the string is suffixed with "ago", or prefixed with a "-", the resulting time span gets
         * subtracted from the current unix timestamp. A "from now" suffix can also be used for
         * readability when adding to the current unix timestamp.
         *
         * @param input "nbf" (Not Before) Claim value to set on the JWT Claims Set.
         */;
        _proto.setNotBefore = function setNotBefore(input) {
          if (typeof input === 'number') {
            this._payload = _extends({}, this._payload, {
              nbf: validateInput('setNotBefore', input)
            });
          } else if (input instanceof Date) {
            this._payload = _extends({}, this._payload, {
              nbf: validateInput('setNotBefore', epoch(input))
            });
          } else {
            this._payload = _extends({}, this._payload, {
              nbf: epoch(new Date()) + secs(input)
            });
          }
          return this;
        }

        /**
         * Set the "exp" (Expiration Time) Claim.
         *
         * - If a `number` is passed as an argument it is used as the claim directly.
         * - If a `Date` instance is passed as an argument it is converted to unix timestamp and used as the
         *   claim.
         * - If a `string` is passed as an argument it is resolved to a time span, and then added to the
         *   current unix timestamp and used as the claim.
         *
         * Format used for time span should be a number followed by a unit, such as "5 minutes" or "1
         * day".
         *
         * Valid units are: "sec", "secs", "second", "seconds", "s", "minute", "minutes", "min", "mins",
         * "m", "hour", "hours", "hr", "hrs", "h", "day", "days", "d", "week", "weeks", "w", "year",
         * "years", "yr", "yrs", and "y". It is not possible to specify months. 365.25 days is used as an
         * alias for a year.
         *
         * If the string is suffixed with "ago", or prefixed with a "-", the resulting time span gets
         * subtracted from the current unix timestamp. A "from now" suffix can also be used for
         * readability when adding to the current unix timestamp.
         *
         * @param input "exp" (Expiration Time) Claim value to set on the JWT Claims Set.
         */;
        _proto.setExpirationTime = function setExpirationTime(input) {
          if (typeof input === 'number') {
            this._payload = _extends({}, this._payload, {
              exp: validateInput('setExpirationTime', input)
            });
          } else if (input instanceof Date) {
            this._payload = _extends({}, this._payload, {
              exp: validateInput('setExpirationTime', epoch(input))
            });
          } else {
            this._payload = _extends({}, this._payload, {
              exp: epoch(new Date()) + secs(input)
            });
          }
          return this;
        }

        /**
         * Set the "iat" (Issued At) Claim.
         *
         * - If no argument is used the current unix timestamp is used as the claim.
         * - If a `number` is passed as an argument it is used as the claim directly.
         * - If a `Date` instance is passed as an argument it is converted to unix timestamp and used as the
         *   claim.
         * - If a `string` is passed as an argument it is resolved to a time span, and then added to the
         *   current unix timestamp and used as the claim.
         *
         * Format used for time span should be a number followed by a unit, such as "5 minutes" or "1
         * day".
         *
         * Valid units are: "sec", "secs", "second", "seconds", "s", "minute", "minutes", "min", "mins",
         * "m", "hour", "hours", "hr", "hrs", "h", "day", "days", "d", "week", "weeks", "w", "year",
         * "years", "yr", "yrs", and "y". It is not possible to specify months. 365.25 days is used as an
         * alias for a year.
         *
         * If the string is suffixed with "ago", or prefixed with a "-", the resulting time span gets
         * subtracted from the current unix timestamp. A "from now" suffix can also be used for
         * readability when adding to the current unix timestamp.
         *
         * @param input "iat" (Expiration Time) Claim value to set on the JWT Claims Set.
         */;
        _proto.setIssuedAt = function setIssuedAt(input) {
          if (typeof input === 'undefined') {
            this._payload = _extends({}, this._payload, {
              iat: epoch(new Date())
            });
          } else if (input instanceof Date) {
            this._payload = _extends({}, this._payload, {
              iat: validateInput('setIssuedAt', epoch(input))
            });
          } else if (typeof input === 'string') {
            this._payload = _extends({}, this._payload, {
              iat: validateInput('setIssuedAt', epoch(new Date()) + secs(input))
            });
          } else {
            this._payload = _extends({}, this._payload, {
              iat: validateInput('setIssuedAt', input)
            });
          }
          return this;
        };
        return ProduceJWT;
      }());
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/puback.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "3bc00iD9L1KMZqngiLrsQZr", "puback", undefined);
      function encode(packet) {
        var packetType = 4;
        var flags = 0;
        return Uint8Array.from([(packetType << 4) + flags, 2, packet.id >> 8, packet.id & 0xff]);
      }
      function decode(buffer, _remainingStart, remainingLength) {
        if (remainingLength !== 2) {
          throw new Error("puback packets must have a length of 2");
        }
        var id = (buffer[2] << 8) + buffer[3];
        return {
          type: "puback",
          id: id
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pubcomp.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "183daYiZgpFSJIfNW1jNId1", "pubcomp", undefined);
      function encode(packet) {
        var packetType = 7;
        var flags = 0;
        return Uint8Array.from([(packetType << 4) + flags, 2, packet.id >> 8, packet.id & 0xff]);
      }
      function decode(buffer, _remainingStart, remainingLength) {
        if (remainingLength !== 2) {
          throw new Error("pubcomp packets must have a length of 2");
        }
        var id = (buffer[2] << 8) + buffer[3];
        return {
          type: "pubcomp",
          id: id
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Public.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './MyMath.ts', './BaseSingleton.ts'], function (exports) {
  var _inheritsLoose, cclegacy, UITransform, sys, Vec3, Vec2, dynamicAtlasManager, sp, js, MyMath, BaseSingleton;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      UITransform = module.UITransform;
      sys = module.sys;
      Vec3 = module.Vec3;
      Vec2 = module.Vec2;
      dynamicAtlasManager = module.dynamicAtlasManager;
      sp = module.sp;
      js = module.js;
    }, function (module) {
      MyMath = module.default;
    }, function (module) {
      BaseSingleton = module.default;
    }],
    execute: function () {
      exports({
        Plug: void 0,
        heClass: heClass,
        setFunctionName: setFunctionName
      });
      cclegacy._RF.push({}, "b304aZGWvhLDpSDQ2k2nzt1", "Public", undefined);
      var Plug;
      (function (_Plug) {
        var PublicData = /*#__PURE__*/function (_BaseSingleton) {
          _inheritsLoose(PublicData, _BaseSingleton);
          function PublicData() {
            var _this;
            for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
              args[_key] = arguments[_key];
            }
            _this = _BaseSingleton.call.apply(_BaseSingleton, [this].concat(args)) || this;
            _this.BaseViewWidth = 720;
            _this.BaseViewHeight = 1280;
            _this.gameVersion = "v1.2.1";
            _this.onlineVersion = "v1.2.1";
            _this.functionName = new Map();
            return _this;
          }
          return PublicData;
        }(BaseSingleton());
        _Plug.PublicData = PublicData;
        var PublicModel = /*#__PURE__*/function (_BaseSingleton2) {
          _inheritsLoose(PublicModel, _BaseSingleton2);
          function PublicModel() {
            return _BaseSingleton2.apply(this, arguments) || this;
          }
          var _proto = PublicModel.prototype;
          /**
           * @param targetNode 需要移動的物件
           * @param moveToNode 移動的目的地
           * @returns 
           */
          _proto.to2DConvertOtherNodeSpaceAR = function to2DConvertOtherNodeSpaceAR(targetNode, moveToNode) {
            // console.log(pos);
            //轉成世界座標
            var worldPoint = moveToNode.parent.getComponent(UITransform).convertToWorldSpaceAR(moveToNode.position);
            // console.log(worldPoint);
            return targetNode.parent.getComponent(UITransform).convertToNodeSpaceAR(worldPoint);
          }
          /**封包整合，自身封包如果與傳遞的封包有相同Key值，自身封包會更新制最新Value 
          * @param _self 需整合封包
          * @param _data 傳遞封包
          */;
          _proto.TwoClassCheckData = function TwoClassCheckData(_self, _data) {
            // console.log(_self);
            // console.log(_data);

            for (var key in _data) {
              if (Object.prototype.hasOwnProperty.call(_self, key)) {
                _self[key] = _data[key];
              }
            }
          };
          _proto.checkApp = function checkApp() {
            // console.log(sys.isNative);
            // console.log(sys.os)
            // console.log(sys.isBrowser)
            if (sys.isNative && !sys.isBrowser) {
              {
                if (sys.os === sys.OS.ANDROID || sys.os === sys.OS.IOS) return true;else return false;
              }
            } else return false;
          };
          _proto.convertVec2ToVec3 = function convertVec2ToVec3(vec2) {
            return new Vec3(vec2.x, vec2.y, 0);
          };
          _proto.convertVec3ToVec2 = function convertVec3ToVec2(vec3) {
            return new Vec2(vec3.x, vec3.y);
          };
          _proto.oneVec3 = function oneVec3(num) {
            return new Vec3(num, num, num);
          }
          /**秒數時間轉換 */
          /**報錯的話Modle請改成ES2020 */;
          _proto.convertTimeToSecond = function convertTimeToSecond(secs, isHR) {
            secs = Math.floor(secs / 1000);
            var hours = isHR ? Math.floor(secs / 3600) : 0;
            var minutes = Math.floor((secs - hours * 3600) / 60);
            var seconds = Math.floor(secs - hours * 3600 - minutes * 60);
            var hrStr = isHR ? hours.toString().padStart(2, '0') + ':' : '';
            var minStr = minutes.toString().padStart(2, '0');
            var secStr = seconds.toString().padStart(2, '0');
            return hrStr + minStr + ':' + secStr;
          };
          _proto.convertMilliToSecond = function convertMilliToSecond(num) {
            return new MyMath().divide(num, 1000);
          }
          /*
          *確認匿名條件式是否在數字、分數、箭頭、數學運算符號、技術符號以及字母符號的 Unicode 字元
          */;
          _proto.checkNicknameCondition = function checkNicknameCondition(str) {
            // let rex = /[\p{P}+\u2100-\u214F]/u
            var rules = /([\s]|[\u3000]|[\u260E-\u26FF]|[\u270A-\u270D]|\ud83c[\ud000-\udfff]|\ud83d[\ud000-\udfff]|\ud83e[\ud000-\udfff])/;
            return rules.test(str);
          }

          /**確認手機格式 */;
          _proto.checkPhoneRegular = function checkPhoneRegular(_string) {
            //please input the test email to see is valid
            var strPhone = _string;

            //判+886
            var phoneRule886 = /^\+[0-9]{1,15}$/;

            //validate ok or not
            if (phoneRule886.test(strPhone)) {
              return true;
            } else {
              return false;
            }
          }
          /**確認信箱格式 */;
          _proto.checkEmailRegular = function checkEmailRegular(_string) {
            //please input the test email to see is valid
            var strEmail = _string;

            //Regular expression Testing
            var emailRule = /^\w+((-\w+)|(\.\w+))*\@[A-Za-z0-9]+((\.|-)[A-Za-z0-9]+)*\.[A-Za-z]+$/;

            //validate ok or not
            if (strEmail.search(emailRule) != -1) {
              return true;
            } else {
              return false;
            }
            // ^\+[0 - 9]{ 1, 15 } $
          }
          /**確認名稱長度 */;
          _proto.checkNameLen = function checkNameLen(name, len) {
            var word = name.split(/\w*/).filter(function (x) {
              return x != "";
            });
            var notWord = name.split(/\W*/).filter(function (x) {
              return x != "";
            });
            var countLen = word.length + Math.floor(notWord.length / 2); //英文數字兩個字元=1個中文字長度
            if (countLen > len) name = this.reName(name, len);
            return name;
          }
          /** 將8位數之後的文字"..."化 */;
          _proto.reName = function reName(name, len) {
            var count_name = '';
            var index = 0;
            var count = 0;
            var cut_name = name.split('');
            while (count < len) {
              count_name = count_name + cut_name[index];
              if (/\w/.test(cut_name[index]))
                //如果遇到英文 只+0.5
                count += 0.5;else count++;
              index++;
            }
            name = count_name + "...";
            return name;
          }

          /**將,文字刪除 */;
          _proto.filterNumberDot = function filterNumberDot(num) {
            var getStrArr = num.toString().split("").filter(function (x) {
              return x != ",";
            });
            var formatStr = "";
            for (var index = 0; index < getStrArr.length; index++) {
              if (/^[0-9]*$/.test(getStrArr[index])) formatStr += getStrArr[index];
            }
            return formatStr;
          }
          /**將Server傳遞封包轉換成Byte */;
          _proto._base64ToBytes = function _base64ToBytes(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array(len);
            for (var i = 0; i < len; i++) {
              bytes[i] = binary_string.charCodeAt(i);
            }
            return bytes;
          }
          /**將Byte轉換成Binary */;
          _proto.convertByteToBinary = function convertByteToBinary(n) {
            var getBin = n.toString(2);
            return getBin;
          }
          /**
           * 
           * @param num 數字
           * @param digits 小數點位數 預設0
           * @returns string
           */;
          _proto.changeKMB = function changeKMB(num, digits) {
            if (digits === void 0) {
              digits = 0;
            }
            var suffixes = ['K', 'M', 'B', 'T', 'P', 'E'];
            if (!num || Number.isNaN(num)) return String(0);
            if (num < 1000) return num.toString();
            var exp = Math.floor(Math.log(num) / Math.log(1000));
            var format = (num / Math.pow(1000, exp)).toString();
            var decimalIndex = format.indexOf('.');
            if (decimalIndex !== -1 && decimalIndex + digits + 1 < format.length) format = format.slice(0, decimalIndex + digits + 1);
            if (format.endsWith('.')) {
              format = format.slice(0, -1);
            }
            // console.warn(format + suffixes[exp - 1]);
            return format + suffixes[exp - 1];
          };
          _proto.getEnumKey = function getEnumKey(enumObject) {
            var enumValues = Object.values(enumObject).filter(function (k) {
              return typeof k === 'number';
            });
            /**代表帶入的Enum的Value值是文字 */
            if (enumValues.length == 0) {
              return Object.keys(enumObject);
            }
            /**代表帶入的Enum的Value值是數字12345 */else {
              return Object.values(enumObject).filter(function (k) {
                return typeof k !== 'number';
              });
            }
          }
          /**不設定默認為true自動合批 */;
          _proto.enabelShader = function enabelShader(bool) {
            dynamicAtlasManager.enabled = bool;
          }
          /**
           * 
           * @param body 封包物件
           * @param _class 類別
           * @param key apiKey
           * @param isDelete 是否刪除sign
           * @returns 
           */;
          _proto.convertSign = function convertSign(body, _class, key, isDelete) {
            if (isDelete === void 0) {
              isDelete = true;
            }
            var sign = new _class();
            this.TwoClassCheckData(sign, body);
            if (isDelete) delete sign.sign;
            var dataWithApiKey = this.sortObj(sign, key);

            // CryptoES.MD5(dataWithApiKey).toString()
            // console.log(dataWithApiKey);
            // console.log(CryptoES.MD5(dataWithApiKey).toString());

            // return CryptoES.MD5(dataWithApiKey).toString()
          };

          _proto.convertMD5 = function convertMD5(str) {
            // return CryptoES.MD5(str).toString()
          }
          /**排序物件順序並且queryString */;
          _proto.sortObj = function sortObj(obj, apiKey) {
            var keyA = Object.keys(obj).sort();
            var querystring = "";
            for (var index = 0; index < keyA.length; index++) {
              querystring += keyA[index] + "=" + obj[keyA[index]];
              if (index != keyA.length - 1) {
                querystring += "&";
              }
            }
            // for (var i in keyA) {
            //encodeURIComponent是ASCII轉換\，但是@也會被轉換所以不使用此方式
            //     // sortObj[keyA[i]] = encodeURIComponent(obj[keyA[i]])

            // }
            querystring += apiKey;
            return querystring;
          };
          _proto.checkStringNull = function checkStringNull(str) {
            return str == "" || str == null || str == undefined ? true : false;
          };
          _proto.getFunctionName = function getFunctionName(func) {
            if (publicDate.functionName.has(func)) return publicDate.functionName.get(func);else console.error("此函數沒有被儲存", func);
          };
          _proto.changeTweenSpeed = function changeTweenSpeed(tween, speed) {
            if (speed === void 0) {
              speed = 1;
            }
            //@ts-ignore
            tween._finalAction._speed = speed;
          };
          _proto.checkHasEnum = function checkHasEnum(type, checkValue) {
            return Object.values(type).includes(checkValue);
          };
          _proto.changeSpinePL = function changeSpinePL(currentSpine, changedata) {
            if (currentSpine.skeletonData.name != changedata.name) {
              throw new Error("spineData不相同無法轉換");
            }
            var tracks = [];
            for (var index = 0; index < currentSpine.getState().tracks.length; index++) {
              if (!currentSpine.getCurrent(index)) continue;
              var curTrack = currentSpine.getCurrent(index);
              var track = new sp.spine.TrackEntry();
              track.trackTime = curTrack.trackTime;
              track.animation.name = curTrack.animation.name;
              track.loop = curTrack.loop;
              track.trackIndex = curTrack.trackIndex;
              tracks.push(track);
            }
            currentSpine.skeletonData = changedata;
            for (var _index = 0; _index < tracks.length; _index++) {
              var _track = tracks[_index];
              currentSpine.setAnimation(_track.trackIndex, _track.animation.name, _track.loop);
              currentSpine.getCurrent(_track.trackIndex).trackTime = _track.trackTime;
            }
          }
          //#region  
          ;

          _proto.handleURLData = function handleURLData(_url) {
            if (_url.split("?")[1] == undefined) return undefined;
            var arr = _url.split("?")[1].split("&");
            var obj = new Object();
            for (var index = 0; index < arr.length; index++) {
              var cut = arr[index].split("=");
              obj[cut[0]] = cut[1];
            }
            return obj;
          }
          //#endregion
          ;

          return PublicModel;
        }(BaseSingleton());
        _Plug.PublicModel = PublicModel;
        var DateTool = /*#__PURE__*/function (_BaseSingleton3) {
          _inheritsLoose(DateTool, _BaseSingleton3);
          function DateTool() {
            return _BaseSingleton3.apply(this, arguments) || this;
          }
          var _proto2 = DateTool.prototype;
          /**
                  * @param str 傳入日期 
                  * @returns ex:1000/11/02 日
                  */
          _proto2.convertDateDay = function convertDateDay(str) {
            // 將字串轉換為Date物件
            var dateObj = new Date(str);
            // 取得日期資訊
            var year = this.convertToROC(dateObj.getFullYear());
            var month = dateObj.getMonth() + 1; // 月份是從0開始的，所以要加1
            var day = dateObj.getDate();
            var daysOfWeek = ['日', '一', '二', '三', '四', '五', '六'];
            var dayOfWeek = daysOfWeek[dateObj.getDay()];
            // 格式化日期
            return year + "/" + month + "/" + day + " (" + dayOfWeek + ")";
          }
          /**
           * 
           * @param str 傳入日期
           * @returns ex:05:30:21 五點30分21秒
           */;
          _proto2.convertDateTime = function convertDateTime(str) {
            // 將字串轉換為Date物件
            var dateObj = new Date(str);
            var sec = dateObj.getSeconds();
            var min = dateObj.getMinutes();
            var hours = dateObj.getHours();

            // 格式化日期
            return hours + ":" + min + ":" + sec;
          }
          /**
           * 轉換國立
           */;
          _proto2.convertToROC = function convertToROC(yearAD) {
            // const ROC_OFFSET = 1911;
            // const isLeapYear = (year) => (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
            // const yearROC = yearAD - ROC_OFFSET + (isLeapYear(yearAD) ? 1 : 0);
            // return yearROC;
            var ROC_OFFSET = 1911;
            var yearROC = yearAD - ROC_OFFSET; // 直接計算民國年份
            return yearROC;
          }
          /**日期相減 */;
          _proto2.convertDateDiff = function convertDateDiff(_date, offsetDay) {
            // sDate1 和 sDate2 是 2016-06-18 格式
            var oDate1 = typeof _date === 'string' ? new Date(_date) : _date;
            return new Date(oDate1.setDate(oDate1.getDate() + offsetDay));
          };
          /**獲得當月最大日期 */
          _proto2.getMonthAllDay = function getMonthAllDay(day) {
            var getDay = typeof day === 'string' ? new Date(day) : day;
            return new Date(getDay.getFullYear(), getDay.getMonth() + 1, 0).getDate();
          };
          return DateTool;
        }(BaseSingleton());
        _Plug.DateTool = DateTool;
        var Model = _Plug.Model = PublicModel.getInstance;
        var publicDate = _Plug.publicDate = PublicData.getInstance;
      })(Plug || (Plug = exports('Plug', {})));
      /**
        将类名赋给该类
      @param target
      */
      function heClass(target) {
        try {
          //@ts-ignore
          var frameInfo = cc['_RF'].peek();
          var script = frameInfo.script;
          js.setClassName(script, target);
        } catch (error) {
          throw Error(error);
        }
      }
      /**取得函數名稱後存起來 */
      function setFunctionName(target, name) {
        if (target.hasOwnProperty(name)) Plug.publicDate.functionName.set(target[name], name);else throw Error("為什麼會沒有這個涵數名稱");
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/publish.ts", ['cc', './length.ts', './utf8.ts'], function (exports) {
  var cclegacy, encodeLength, encodeUTF8String, decodeUTF8String;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      encodeLength = module.encodeLength;
    }, function (module) {
      encodeUTF8String = module.encodeUTF8String;
      decodeUTF8String = module.decodeUTF8String;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "b6d70ubQ8tIOJCBCCVOj+2w", "publish", undefined);
      function encode(packet, utf8Encoder) {
        var packetType = 3;
        var qos = packet.qos || 0;
        var flags = (packet.dup ? 8 : 0) + (qos & 2 ? 4 : 0) + (qos & 1 ? 2 : 0) + (packet.retain ? 1 : 0);
        var variableHeader = [].concat(encodeUTF8String(packet.topic, utf8Encoder));
        if (qos === 1 || qos === 2) {
          if (typeof packet.id !== "number" || packet.id < 1) {
            throw new Error("when qos is 1 or 2, packet must have id");
          }
          variableHeader.push(packet.id >> 8, packet.id & 0xff);
        }
        var payload = packet.payload;
        if (typeof payload === "string") {
          payload = utf8Encoder.encode(payload);
        }
        var fixedHeader = [packetType << 4 | flags].concat(encodeLength(variableHeader.length + payload.length));
        return Uint8Array.from([].concat(fixedHeader, variableHeader, payload));
      }
      function decode(buffer, remainingStart, remainingLength, utf8Decoder) {
        var flags = buffer[0] & 0x0f;
        var dup = !!(flags & 8);
        var qos = (flags & 6) >> 1;
        var retain = !!(flags & 1);
        if (qos !== 0 && qos !== 1 && qos !== 2) {
          throw new Error("invalid qos");
        }
        var topicStart = remainingStart;
        var decodedTopic = decodeUTF8String(buffer, topicStart, utf8Decoder);
        var topic = decodedTopic.value;
        var id = 0;
        var payloadStart = topicStart + decodedTopic.length;
        if (qos > 0) {
          var idStart = payloadStart;
          id = (buffer[idStart] << 8) + buffer[idStart + 1];
          payloadStart += 2;
        }
        var payload = buffer.slice(payloadStart, remainingStart + remainingLength);
        return {
          type: "publish",
          topic: topic,
          payload: payload,
          dup: dup,
          retain: retain,
          qos: qos,
          id: id
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pubrec.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "5e1dbPO2ARLT6pkZJb71xfP", "pubrec", undefined);
      function encode(packet) {
        var packetType = 5;
        var flags = 0;
        return Uint8Array.from([(packetType << 4) + flags, 2, packet.id >> 8, packet.id & 0xff]);
      }
      function decode(buffer, _remainingStart, remainingLength) {
        if (remainingLength !== 2) {
          throw new Error("pubrec packets must have a length of 2");
        }
        var id = (buffer[2] << 8) + buffer[3];
        return {
          type: "pubrec",
          id: id
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/pubrel.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "b6caeEhiw1MAbdBaV5JvAwg", "pubrel", undefined);
      function encode(packet) {
        var packetType = 6;
        var flags = 2;
        return Uint8Array.from([(packetType << 4) + flags, 2, packet.id >> 8, packet.id & 0xff]);
      }
      function decode(buffer, _remainingStart, remainingLength) {
        if (remainingLength !== 2) {
          throw new Error("pubrel packets must have a length of 2");
        }
        var id = (buffer[2] << 8) + buffer[3];
        return {
          type: "pubrel",
          id: id
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/rabbit-legacy.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, StreamCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      StreamCipher = module.StreamCipher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "536d5XxTk9ErIFvDMR589+D", "rabbit-legacy", undefined);

      // Reusable objects
      var S = [];
      var C_ = [];
      var G = [];
      function nextState() {
        // Shortcuts
        var X = this._X;
        var C = this._C;

        // Save old counter values
        for (var i = 0; i < 8; i += 1) {
          C_[i] = C[i];
        }

        // Calculate new counter values
        C[0] = C[0] + 0x4d34d34d + this._b | 0;
        C[1] = C[1] + 0xd34d34d3 + (C[0] >>> 0 < C_[0] >>> 0 ? 1 : 0) | 0;
        C[2] = C[2] + 0x34d34d34 + (C[1] >>> 0 < C_[1] >>> 0 ? 1 : 0) | 0;
        C[3] = C[3] + 0x4d34d34d + (C[2] >>> 0 < C_[2] >>> 0 ? 1 : 0) | 0;
        C[4] = C[4] + 0xd34d34d3 + (C[3] >>> 0 < C_[3] >>> 0 ? 1 : 0) | 0;
        C[5] = C[5] + 0x34d34d34 + (C[4] >>> 0 < C_[4] >>> 0 ? 1 : 0) | 0;
        C[6] = C[6] + 0x4d34d34d + (C[5] >>> 0 < C_[5] >>> 0 ? 1 : 0) | 0;
        C[7] = C[7] + 0xd34d34d3 + (C[6] >>> 0 < C_[6] >>> 0 ? 1 : 0) | 0;
        this._b = C[7] >>> 0 < C_[7] >>> 0 ? 1 : 0;

        // Calculate the g-values
        for (var _i = 0; _i < 8; _i += 1) {
          var gx = X[_i] + C[_i];

          // Construct high and low argument for squaring
          var ga = gx & 0xffff;
          var gb = gx >>> 16;

          // Calculate high and low result of squaring
          var gh = ((ga * ga >>> 17) + ga * gb >>> 15) + gb * gb;
          var gl = ((gx & 0xffff0000) * gx | 0) + ((gx & 0x0000ffff) * gx | 0);

          // High XOR low
          G[_i] = gh ^ gl;
        }

        // Calculate new state values
        X[0] = G[0] + (G[7] << 16 | G[7] >>> 16) + (G[6] << 16 | G[6] >>> 16) | 0;
        X[1] = G[1] + (G[0] << 8 | G[0] >>> 24) + G[7] | 0;
        X[2] = G[2] + (G[1] << 16 | G[1] >>> 16) + (G[0] << 16 | G[0] >>> 16) | 0;
        X[3] = G[3] + (G[2] << 8 | G[2] >>> 24) + G[1] | 0;
        X[4] = G[4] + (G[3] << 16 | G[3] >>> 16) + (G[2] << 16 | G[2] >>> 16) | 0;
        X[5] = G[5] + (G[4] << 8 | G[4] >>> 24) + G[3] | 0;
        X[6] = G[6] + (G[5] << 16 | G[5] >>> 16) + (G[4] << 16 | G[4] >>> 16) | 0;
        X[7] = G[7] + (G[6] << 8 | G[6] >>> 24) + G[5] | 0;
      }

      /**
       * Rabbit stream cipher algorithm.
       *
       * This is a legacy version that neglected to convert the key to little-endian.
       * This error doesn't affect the cipher's security,
       * but it does affect its compatibility with other implementations.
       */
      var RabbitLegacyAlgo = exports('RabbitLegacyAlgo', /*#__PURE__*/function (_StreamCipher) {
        _inheritsLoose(RabbitLegacyAlgo, _StreamCipher);
        function RabbitLegacyAlgo() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StreamCipher.call.apply(_StreamCipher, [this].concat(args)) || this;
          _this.blockSize = 128 / 32;
          _this.ivSize = 64 / 32;
          return _this;
        }
        var _proto = RabbitLegacyAlgo.prototype;
        _proto._doReset = function _doReset() {
          // Shortcuts
          var K = this._key.words;
          var iv = this.cfg.iv;

          // Generate initial state values
          this._X = [K[0], K[3] << 16 | K[2] >>> 16, K[1], K[0] << 16 | K[3] >>> 16, K[2], K[1] << 16 | K[0] >>> 16, K[3], K[2] << 16 | K[1] >>> 16];
          var X = this._X;

          // Generate initial counter values
          this._C = [K[2] << 16 | K[2] >>> 16, K[0] & 0xffff0000 | K[1] & 0x0000ffff, K[3] << 16 | K[3] >>> 16, K[1] & 0xffff0000 | K[2] & 0x0000ffff, K[0] << 16 | K[0] >>> 16, K[2] & 0xffff0000 | K[3] & 0x0000ffff, K[1] << 16 | K[1] >>> 16, K[3] & 0xffff0000 | K[0] & 0x0000ffff];
          var C = this._C;

          // Carry bit
          this._b = 0;

          // Iterate the system four times
          for (var i = 0; i < 4; i += 1) {
            nextState.call(this);
          }

          // Modify the counters
          for (var _i2 = 0; _i2 < 8; _i2 += 1) {
            C[_i2] ^= X[_i2 + 4 & 7];
          }

          // IV setup
          if (iv) {
            // Shortcuts
            var IV = iv.words;
            var IV_0 = IV[0];
            var IV_1 = IV[1];

            // Generate four subvectors
            var i0 = (IV_0 << 8 | IV_0 >>> 24) & 0x00ff00ff | (IV_0 << 24 | IV_0 >>> 8) & 0xff00ff00;
            var i2 = (IV_1 << 8 | IV_1 >>> 24) & 0x00ff00ff | (IV_1 << 24 | IV_1 >>> 8) & 0xff00ff00;
            var i1 = i0 >>> 16 | i2 & 0xffff0000;
            var i3 = i2 << 16 | i0 & 0x0000ffff;

            // Modify counter values
            C[0] ^= i0;
            C[1] ^= i1;
            C[2] ^= i2;
            C[3] ^= i3;
            C[4] ^= i0;
            C[5] ^= i1;
            C[6] ^= i2;
            C[7] ^= i3;

            // Iterate the system four times
            for (var _i3 = 0; _i3 < 4; _i3 += 1) {
              nextState.call(this);
            }
          }
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Shortcut
          var X = this._X;

          // Iterate the system
          nextState.call(this);

          // Generate four keystream words
          S[0] = X[0] ^ X[5] >>> 16 ^ X[3] << 16;
          S[1] = X[2] ^ X[7] >>> 16 ^ X[5] << 16;
          S[2] = X[4] ^ X[1] >>> 16 ^ X[7] << 16;
          S[3] = X[6] ^ X[3] >>> 16 ^ X[1] << 16;
          for (var i = 0; i < 4; i += 1) {
            // Swap endian
            S[i] = (S[i] << 8 | S[i] >>> 24) & 0x00ff00ff | (S[i] << 24 | S[i] >>> 8) & 0xff00ff00;

            // Encrypt
            _M[offset + i] ^= S[i];
          }
        };
        return RabbitLegacyAlgo;
      }(StreamCipher));

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.RabbitLegacy.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.RabbitLegacy.decrypt(ciphertext, key, cfg);
       */
      var RabbitLegacy = exports('RabbitLegacy', StreamCipher._createHelper(RabbitLegacyAlgo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/rabbit.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, StreamCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      StreamCipher = module.StreamCipher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "8c3805Q3PpMRr0L4K/I79lc", "rabbit", undefined);

      // Reusable objects
      var S = [];
      var C_ = [];
      var G = [];
      function nextState() {
        // Shortcuts
        var X = this._X;
        var C = this._C;

        // Save old counter values
        for (var i = 0; i < 8; i += 1) {
          C_[i] = C[i];
        }

        // Calculate new counter values
        C[0] = C[0] + 0x4d34d34d + this._b | 0;
        C[1] = C[1] + 0xd34d34d3 + (C[0] >>> 0 < C_[0] >>> 0 ? 1 : 0) | 0;
        C[2] = C[2] + 0x34d34d34 + (C[1] >>> 0 < C_[1] >>> 0 ? 1 : 0) | 0;
        C[3] = C[3] + 0x4d34d34d + (C[2] >>> 0 < C_[2] >>> 0 ? 1 : 0) | 0;
        C[4] = C[4] + 0xd34d34d3 + (C[3] >>> 0 < C_[3] >>> 0 ? 1 : 0) | 0;
        C[5] = C[5] + 0x34d34d34 + (C[4] >>> 0 < C_[4] >>> 0 ? 1 : 0) | 0;
        C[6] = C[6] + 0x4d34d34d + (C[5] >>> 0 < C_[5] >>> 0 ? 1 : 0) | 0;
        C[7] = C[7] + 0xd34d34d3 + (C[6] >>> 0 < C_[6] >>> 0 ? 1 : 0) | 0;
        this._b = C[7] >>> 0 < C_[7] >>> 0 ? 1 : 0;

        // Calculate the g-values
        for (var _i = 0; _i < 8; _i += 1) {
          var gx = X[_i] + C[_i];

          // Construct high and low argument for squaring
          var ga = gx & 0xffff;
          var gb = gx >>> 16;

          // Calculate high and low result of squaring
          var gh = ((ga * ga >>> 17) + ga * gb >>> 15) + gb * gb;
          var gl = ((gx & 0xffff0000) * gx | 0) + ((gx & 0x0000ffff) * gx | 0);

          // High XOR low
          G[_i] = gh ^ gl;
        }

        // Calculate new state values
        X[0] = G[0] + (G[7] << 16 | G[7] >>> 16) + (G[6] << 16 | G[6] >>> 16) | 0;
        X[1] = G[1] + (G[0] << 8 | G[0] >>> 24) + G[7] | 0;
        X[2] = G[2] + (G[1] << 16 | G[1] >>> 16) + (G[0] << 16 | G[0] >>> 16) | 0;
        X[3] = G[3] + (G[2] << 8 | G[2] >>> 24) + G[1] | 0;
        X[4] = G[4] + (G[3] << 16 | G[3] >>> 16) + (G[2] << 16 | G[2] >>> 16) | 0;
        X[5] = G[5] + (G[4] << 8 | G[4] >>> 24) + G[3] | 0;
        X[6] = G[6] + (G[5] << 16 | G[5] >>> 16) + (G[4] << 16 | G[4] >>> 16) | 0;
        X[7] = G[7] + (G[6] << 8 | G[6] >>> 24) + G[5] | 0;
      }

      /**
       * Rabbit stream cipher algorithm
       */
      var RabbitAlgo = exports('RabbitAlgo', /*#__PURE__*/function (_StreamCipher) {
        _inheritsLoose(RabbitAlgo, _StreamCipher);
        function RabbitAlgo() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _StreamCipher.call.apply(_StreamCipher, [this].concat(args)) || this;
          _this.blockSize = 128 / 32;
          _this.ivSize = 64 / 32;
          return _this;
        }
        var _proto = RabbitAlgo.prototype;
        _proto._doReset = function _doReset() {
          // Shortcuts
          var K = this._key.words;
          var iv = this.cfg.iv;

          // Swap endian
          for (var i = 0; i < 4; i += 1) {
            K[i] = (K[i] << 8 | K[i] >>> 24) & 0x00ff00ff | (K[i] << 24 | K[i] >>> 8) & 0xff00ff00;
          }

          // Generate initial state values
          this._X = [K[0], K[3] << 16 | K[2] >>> 16, K[1], K[0] << 16 | K[3] >>> 16, K[2], K[1] << 16 | K[0] >>> 16, K[3], K[2] << 16 | K[1] >>> 16];
          var X = this._X;

          // Generate initial counter values
          this._C = [K[2] << 16 | K[2] >>> 16, K[0] & 0xffff0000 | K[1] & 0x0000ffff, K[3] << 16 | K[3] >>> 16, K[1] & 0xffff0000 | K[2] & 0x0000ffff, K[0] << 16 | K[0] >>> 16, K[2] & 0xffff0000 | K[3] & 0x0000ffff, K[1] << 16 | K[1] >>> 16, K[3] & 0xffff0000 | K[0] & 0x0000ffff];
          var C = this._C;

          // Carry bit
          this._b = 0;

          // Iterate the system four times
          for (var _i2 = 0; _i2 < 4; _i2 += 1) {
            nextState.call(this);
          }

          // Modify the counters
          for (var _i3 = 0; _i3 < 8; _i3 += 1) {
            C[_i3] ^= X[_i3 + 4 & 7];
          }

          // IV setup
          if (iv) {
            // Shortcuts
            var IV = iv.words;
            var IV_0 = IV[0];
            var IV_1 = IV[1];

            // Generate four subvectors
            var i0 = (IV_0 << 8 | IV_0 >>> 24) & 0x00ff00ff | (IV_0 << 24 | IV_0 >>> 8) & 0xff00ff00;
            var i2 = (IV_1 << 8 | IV_1 >>> 24) & 0x00ff00ff | (IV_1 << 24 | IV_1 >>> 8) & 0xff00ff00;
            var i1 = i0 >>> 16 | i2 & 0xffff0000;
            var i3 = i2 << 16 | i0 & 0x0000ffff;

            // Modify counter values
            C[0] ^= i0;
            C[1] ^= i1;
            C[2] ^= i2;
            C[3] ^= i3;
            C[4] ^= i0;
            C[5] ^= i1;
            C[6] ^= i2;
            C[7] ^= i3;

            // Iterate the system four times
            for (var _i4 = 0; _i4 < 4; _i4 += 1) {
              nextState.call(this);
            }
          }
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Shortcut
          var X = this._X;

          // Iterate the system
          nextState.call(this);

          // Generate four keystream words
          S[0] = X[0] ^ X[5] >>> 16 ^ X[3] << 16;
          S[1] = X[2] ^ X[7] >>> 16 ^ X[5] << 16;
          S[2] = X[4] ^ X[1] >>> 16 ^ X[7] << 16;
          S[3] = X[6] ^ X[3] >>> 16 ^ X[1] << 16;
          for (var i = 0; i < 4; i += 1) {
            // Swap endian
            S[i] = (S[i] << 8 | S[i] >>> 24) & 0x00ff00ff | (S[i] << 24 | S[i] >>> 8) & 0xff00ff00;

            // Encrypt
            _M[offset + i] ^= S[i];
          }
        };
        return RabbitAlgo;
      }(StreamCipher));

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
       */
      var Rabbit = exports('Rabbit', StreamCipher._createHelper(RabbitAlgo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/rc4.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, StreamCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      StreamCipher = module.StreamCipher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "35de5FB8dBGoYyvzVbh5nsv", "rc4", undefined);
      function generateKeystreamWord() {
        // Shortcuts
        var S = this._S;
        var i = this._i;
        var j = this._j;

        // Generate keystream word
        var keystreamWord = 0;
        for (var n = 0; n < 4; n += 1) {
          i = (i + 1) % 256;
          j = (j + S[i]) % 256;

          // Swap
          var t = S[i];
          S[i] = S[j];
          S[j] = t;
          keystreamWord |= S[(S[i] + S[j]) % 256] << 24 - n * 8;
        }

        // Update counters
        this._i = i;
        this._j = j;
        return keystreamWord;
      }

      /**
       * RC4 stream cipher algorithm.
       */
      var RC4Algo = exports('RC4Algo', /*#__PURE__*/function (_StreamCipher) {
        _inheritsLoose(RC4Algo, _StreamCipher);
        function RC4Algo() {
          return _StreamCipher.apply(this, arguments) || this;
        }
        var _proto = RC4Algo.prototype;
        _proto._doReset = function _doReset() {
          // Shortcuts
          var key = this._key;
          var keyWords = key.words;
          var keySigBytes = key.sigBytes;

          // Init sbox
          this._S = [];
          var S = this._S;
          for (var i = 0; i < 256; i += 1) {
            S[i] = i;
          }

          // Key setup
          for (var _i = 0, j = 0; _i < 256; _i += 1) {
            var keyByteIndex = _i % keySigBytes;
            var keyByte = keyWords[keyByteIndex >>> 2] >>> 24 - keyByteIndex % 4 * 8 & 0xff;
            j = (j + S[_i] + keyByte) % 256;

            // Swap
            var t = S[_i];
            S[_i] = S[j];
            S[j] = t;
          }

          // Counters
          this._j = 0;
          this._i = this._j;
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;
          _M[offset] ^= generateKeystreamWord.call(this);
        };
        return RC4Algo;
      }(StreamCipher));
      RC4Algo.keySize = 256 / 32;
      RC4Algo.ivSize = 0;

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
       */
      var RC4 = exports('RC4', StreamCipher._createHelper(RC4Algo));

      /**
       * Modified RC4 stream cipher algorithm.
       */
      var RC4DropAlgo = exports('RC4DropAlgo', /*#__PURE__*/function (_RC4Algo) {
        _inheritsLoose(RC4DropAlgo, _RC4Algo);
        function RC4DropAlgo() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _RC4Algo.call.apply(_RC4Algo, [this].concat(args)) || this;

          /**
           * Configuration options.
           *
           * @property {number} drop The number of keystream words to drop. Default 192
           */
          Object.assign(_this.cfg, {
            drop: 192
          });
          return _this;
        }
        var _proto2 = RC4DropAlgo.prototype;
        _proto2._doReset = function _doReset() {
          _RC4Algo.prototype._doReset.call(this);

          // Drop
          for (var i = this.cfg.drop; i > 0; i -= 1) {
            generateKeystreamWord.call(this);
          }
        };
        return RC4DropAlgo;
      }(RC4Algo));

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
       */
      var RC4Drop = exports('RC4Drop', StreamCipher._createHelper(RC4DropAlgo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/Request.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _asyncToGenerator, _regeneratorRuntime, cclegacy;
  return {
    setters: [function (module) {
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "e17370vS3ZMWY2aU0AXu83h", "Request", undefined);
      var Request = exports('default', /*#__PURE__*/function () {
        /**避免傳遞過長，因此在初始化時就先記錄app狀況 */
        function Request(appBool) {
          if (appBool === void 0) {
            appBool = false;
          }
          this.method = Method.GET;
          this.headers = new Headers();
          this.body = void 0;
          this.isApp = false;
          this.isApp = appBool;
        }
        var _proto = Request.prototype;
        _proto.setMethod = function setMethod(_method) {
          this.method = _method;
          return this;
        };
        _proto.setHeaders = function setHeaders(_headers) {
          this.headers = _headers;
          return this;
        };
        _proto.setToken = function setToken(str) {
          this.headers.Authorization = "Bearer " + str;
          return this;
        };
        _proto.setBody = function setBody(_body) {
          this.body = _body;
          return this;
        };
        _proto.deletother = function deletother() {
          delete this.headers.Accept;
          delete this.headers.Authorization;
          return this;
        };
        _proto.deletContentType = function deletContentType() {
          delete this.headers["Content-Type"];
          return this;
        };
        _proto.setContentType = function setContentType(type) {
          this.headers["Content-Type"] = type;
          return this;
        };
        _proto.fetchData = function fetchData(_url, callback) {
          var _this = this;
          // console.log(_url);
          // console.log(_url.split("?"));
          // console.log(_url.split("?")[0].split("/"));
          // console.log(_url.split("?")[0].split("/")[_url.split("?")[0].split("/").length]);
          console.log(this);
          return new Promise(function (resolve, reject) {
            var data;
            fetch(_url, _this).then(function (response) {
              /**避免轉json有時候會因為沒資料直接錯誤 */
              try {
                return response.json();
              } catch (error) {
                return null;
              }
            })
            // .then(response => response.json())
            ["catch"](function (err) {
              return console.error(err);
            }).then(function (response) {
              return data = response;
            }) /**必定會接，所以先接成區域變數，好做後面的流程 */.then(function (response) {
              return console.log("\u8CC7\u6599\u540D\u7A31\uFF1A" + _url.split("?")[0].split("/")[_url.split("?")[0].split("/").length - 1]);
            }).then(function (response) {
              try {
                console.log("\u8CC7\u6599\u5167\u5BB9", data);
                if (callback) callback(data);
                resolve(data);
              } catch (error) {
                resolve(new PacketData(new Status("999")));
                console.log(error);
              }
            });
          });
        };
        _proto.XMLData = function XMLData(url, callback) {
          var _this2 = this;
          console.log("開始", url);
          return new Promise(function (resolve, reject) {
            var xhr = new XMLHttpRequest();
            // console.error(this.method);
            // console.error(this.headers["Content-Type"]);
            xhr.setRequestHeader("Content-Type", _this2.headers["Content-Type"]);
            xhr.setRequestHeader("Accept", _this2.headers["Accept"]);
            xhr.setRequestHeader("Authorization", _this2.headers["Authorization"]);
            if (xhr.overrideMimeType) xhr.overrideMimeType('text\/plain; charset=utf-8');
            xhr.onload = function () {
              console.log(xhr);
              if (xhr.readyState === 4 && xhr.status === 200) {
                try {
                  console.warn(JSON.parse(xhr.response));
                  if (callback) callback(JSON.parse(xhr.response));
                  resolve(JSON.parse(xhr.response));
                } catch (error) {
                  resolve(new PacketData(new Status("999")));
                  console.error("Format error", xhr);
                }
              } else {
                resolve(new PacketData(new Status(xhr.status.toString())));
                console.error("connet error", xhr);
              }
            };
            xhr.open(_this2.method, url, true);
            if (_this2.method == Method.POST) xhr.send(_this2.body);else xhr.send();
          });
        };
        _proto.SwitchGetData = /*#__PURE__*/function () {
          var _SwitchGetData = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee2(url, callback) {
            var _this3 = this;
            return _regeneratorRuntime().wrap(function _callee2$(_context2) {
              while (1) switch (_context2.prev = _context2.next) {
                case 0:
                  return _context2.abrupt("return", new Promise( /*#__PURE__*/_asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(resolve, reject) {
                    return _regeneratorRuntime().wrap(function _callee$(_context) {
                      while (1) switch (_context.prev = _context.next) {
                        case 0:
                          if (!_this3.isApp) {
                            _context.next = 8;
                            break;
                          }
                          _context.t0 = resolve;
                          _context.next = 4;
                          return _this3.XMLData(url, callback);
                        case 4:
                          _context.t1 = _context.sent;
                          (0, _context.t0)(_context.t1);
                          _context.next = 13;
                          break;
                        case 8:
                          _context.t2 = resolve;
                          _context.next = 11;
                          return _this3.fetchData(url, callback);
                        case 11:
                          _context.t3 = _context.sent;
                          (0, _context.t2)(_context.t3);
                        case 13:
                        case "end":
                          return _context.stop();
                      }
                    }, _callee);
                  }))));
                case 1:
                case "end":
                  return _context2.stop();
              }
            }, _callee2);
          }));
          function SwitchGetData(_x, _x2) {
            return _SwitchGetData.apply(this, arguments);
          }
          return SwitchGetData;
        }();
        return Request;
      }());
      var Method = exports('Method', /*#__PURE__*/function (Method) {
        Method["GET"] = "GET";
        Method["POST"] = "POST";
        return Method;
      }({}));
      var ContentType = exports('ContentType', /*#__PURE__*/function (ContentType) {
        ContentType["Default"] = "";
        ContentType["Json"] = "application/json, text/plain, */*";
        ContentType["FormData"] = "multipart/form-data";
        ContentType["Form"] = "application/x-www-form-urlencoded";
        return ContentType;
      }({}));
      var Headers = function Headers() {
        this["Content-Type"] = ContentType.Json;
        this["Accept"] = "application/json;charset=UTF-8";
        this["Authorization"] = "";
      };
      var PacketData = function PacketData(_state) {
        this.Status = void 0;
        this.Status = _state;
      };
      var Status = function Status(_code, _message) {
        this.Code = void 0;
        this.Message = void 0;
        this.Timestamp = void 0;
        this.TraceCode = void 0;
        this.Code = _code;
        this.Message = _message;
      };
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/RequestContorl.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseComponent.ts', './EventMng.ts', './M10Enum.ts', './M10SFGamer.ts', './BasicEnum.ts', './RequestData2.ts'], function (exports) {
  var _inheritsLoose, cclegacy, _decorator, random, BaseComponent, EventMng, NotificationType, GameEnum, M10Select, IdentityType, BasicEnum, SelectResult, OrderResult, M10Result;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      random = module.random;
    }, function (module) {
      BaseComponent = module.default;
    }, function (module) {
      EventMng = module.default;
      NotificationType = module.NotificationType;
    }, function (module) {
      GameEnum = module.GameEnum;
      M10Select = module.M10Select;
    }, function (module) {
      IdentityType = module.IdentityType;
    }, function (module) {
      BasicEnum = module.BasicEnum;
    }, function (module) {
      SelectResult = module.SelectResult;
      OrderResult = module.OrderResult;
      M10Result = module.M10Result;
    }],
    execute: function () {
      var _dec, _class;
      cclegacy._RF.push({}, "d1e977IHVBDdqqFsaAxxXZ8", "RequestContorl", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var RequestContorl = exports('default', (_dec = ccclass('RequestContorl'), _dec(_class = /*#__PURE__*/function (_BaseComponent) {
        _inheritsLoose(RequestContorl, _BaseComponent);
        function RequestContorl() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseComponent.call.apply(_BaseComponent, [this].concat(args)) || this;
          _this.playerDice = void 0;
          _this.enemyDice = void 0;
          _this.order = null;
          return _this;
        }
        var _proto = RequestContorl.prototype;
        _proto.onLoad = function onLoad() {
          this.setEvent(BasicEnum.SendAPI, this.sendAPI);
          EventMng.getInstance.setEvent(NotificationType.Game, GameEnum.SendAPI, this.sendAPI, this);
        };
        _proto.sendAPI = function sendAPI(sendDate, gameEnum) {
          console.log("傳傳送封包", sendDate);
          if (gameEnum) {
            switch (gameEnum) {
              case GameEnum.CheckOrder:
                var orderR = new OrderResult();
                if (this.order == null) {
                  orderR.order = this.order = Math.floor(random() * 2);
                  this.playerDice = new Array(5);
                  this.enemyDice = new Array(5);
                } else orderR.order = this.order = this.order == IdentityType.Enemy_Num ? IdentityType.Player_Num : IdentityType.Enemy_Num;
                orderR.playerDice = this.playerDice = this.initDice(this.playerDice.length);
                orderR.enemyDice = this.enemyDice = this.initDice(this.enemyDice.length);
                if (orderR.order == IdentityType.Enemy_Num) {
                  var selectStr = Object.keys(M10Select);
                  orderR.roundSelect = selectStr[Math.floor(random() * selectStr.length)];
                }
                EventMng.getInstance.emit(NotificationType.Game, GameEnum.CheckOrder, orderR);
                break;
              case GameEnum.CheckSelect:
                var _sendDate = sendDate;
                var selectR = new SelectResult();
                selectR.order = this.order;
                selectR.roundSelect = _sendDate.roundSelect;
                selectR.enemyDice = this.enemyDice;
                selectR.playerDice = this.playerDice;
                selectR.changeEnemyDice = this.filterDic(this.enemyDice, _sendDate.roundSelect);
                selectR.changePlayerDice = this.filterDic(this.playerDice, _sendDate.roundSelect);
                this.playerDice = selectR.changePlayerDice.filter(Boolean);
                this.enemyDice = selectR.changeEnemyDice.filter(Boolean);
                if (this.playerDice.length == 0) selectR.winPoint = -1;
                if (this.enemyDice.length == 0) selectR.winPoint = 1;
                if (this.playerDice.length == 0 && this.enemyDice.length == 0) selectR.winPoint = 0;
                if (this.playerDice.length == 0 || this.enemyDice.length == 0) this.order = null;
                console.log("回傳", selectR);
                EventMng.getInstance.emit(NotificationType.Game, GameEnum.CheckSelect, selectR);
                break;
            }
          } else {
            var resultDate = new M10Result();
            this.eventEmit(BasicEnum.Result, resultDate);
          }
          // do {
          //     // date.winPoint = random() > .5 ? 0 : 1
          //     date.heartCard = Math.floor(1 + random() * 13)
          //     date.spadeCard = Math.floor(1 + random() * 13)
          // }
          // while (date.heartCard == date.spadeCard)
          // //預設玩家都是Hart

          // if (this.pokerOffsetNum(date.heartCard) > this.pokerOffsetNum(date.spadeCard)) {

          // }
          // else if (this.pokerOffsetNum(date.spadeCard) > this.pokerOffsetNum(date.heartCard)) {

          // }
          // else
          //     date.winPoint = 0

          //如果=0 ，代表需要empty獲勝，有win代表player獲勝，如果比大小沒有達成的話，重新random
          // while (this.checkWiner(date)) {
          //     console.log(this.checkWiner(date));

          //     date.playerCard = Math.floor(1 + random() * 13)
          //     date.emptyCard = Math.floor(1 + random() * 13)
          // }
          /**在做偷偷調換 */

          // console.log(date);

          // let req = new Request(sys.isMobile)

          // switch (apiType) {
          //     case GameEnum.Request:
          //         // req.setToken("");
          //         // req.SwitchGetData(`http://google.com`)
          //         break;
          // }
        };

        _proto.filterDic = function filterDic(dices, selectType) {
          var arr = dices.slice();
          var func;
          switch (selectType) {
            case M10Select.Big:
              func = function func(num) {
                return num < 4;
              };
              break;
            case M10Select.Small:
              func = function func(num) {
                return num > 3;
              };
              break;
            case M10Select.Red:
              func = function func(num) {
                return num != 1 && num != 4;
              };
              break;
            case M10Select.Black:
              func = function func(num) {
                return num == 1 || num == 4;
              };
              break;
            case M10Select.Even:
              func = function func(num) {
                return num % 2 == 0;
              };
              break;
            case M10Select.Odd:
              func = function func(num) {
                return num % 2 != 0;
              };
              break;
          }
          for (var index = 0; index < arr.length; index++) {
            if (!func(arr[index])) arr[index] = null;
          }
          return arr;
        };
        _proto.initDice = function initDice(len) {
          var array = [];
          while (array.length < len) {
            var randomNumber = Math.floor(Math.random() * 6) + 1; // 生成1到6的隨機數字
            if (!array.includes(randomNumber)) {
              array.push(randomNumber);
            }
          }
          return array;
        };
        return RequestContorl;
      }(BaseComponent)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/RequestData.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        APIKey: void 0,
        APIUrl: void 0,
        Body: void 0
      });
      cclegacy._RF.push({}, "1a176wJxm9C2454tgBx5AK3", "RequestData", undefined);
      var Body;
      (function (_Body) {
        var NoMemberID;
        (function (_NoMemberID) {
          var base = function base() {
            this.sign = void 0;
          };
          _NoMemberID.base = base;
        })(NoMemberID || (NoMemberID = _Body.NoMemberID || (_Body.NoMemberID = {})));
        var NeedToken;
        (function (_NeedToken) {
          var base = function base() {
            this.sign = void 0;
            this.memberId = void 0;
          };
          _NeedToken.base = base;
        })(NeedToken || (NeedToken = _Body.NeedToken || (_Body.NeedToken = {})));
      })(Body || (Body = exports('Body', {})));
      var APIUrl;
      (function (_APIUrl) {
        var GPG = function GPG() {
          this.PlayAPI = "";
          this.QAPlayAPI = "";
        };
        _APIUrl.GPG = GPG;
      })(APIUrl || (APIUrl = exports('APIUrl', {})));
      var API = exports('API', /*#__PURE__*/function (API) {
        API["test"] = "www.google.com";
        return API;
      }({}));
      var APIKey;
      (function (_APIKey) {
        var GPG = function GPG() {
          this.QA = "";
          this.Online = "";
        };
        _APIKey.GPG = GPG;
      })(APIKey || (APIKey = exports('APIKey', {})));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/RequestData2.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "5c486L9D55F3bO1tRRAmxfN", "RequestData", undefined);
      /**最終 */
      var M10Result = exports('M10Result', function M10Result() {
        this.winPoint = void 0;
        this.enemyDice = [-1, -1, -1, -1, -1];
        this.playerDice = [0, 0, 0, 0, 0];
      });
      var OrderResult = exports('OrderResult', function OrderResult() {
        this.order = void 0;
        this.enemyDice = [-1, -1, -1, -1, -1];
        this.playerDice = [0, 0, 0, 0, 0];
        /**假設系統先才會有 */
        this.roundSelect = void 0;
      });
      var SelectResult = exports('SelectResult', function SelectResult() {
        this.order = void 0;
        this.enemyDice = [-1, -1, -1, -1, -1];
        this.playerDice = [0, 0, 0, 0, 0];
        this.changeEnemyDice = [-1, -1, -1, -1, -1];
        this.changePlayerDice = [0, 0, 0, 0, 0];
        this.roundSelect = void 0;
        this.winPoint = void 0;
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ResponseData.ts", ['cc'], function () {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "f805dlq4ntGD6Ge+ZLHx8/e", "ResponseData", undefined);
      /**只有純訊息沒有資料 */
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ripemd160.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, Hasher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
      Hasher = module.Hasher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "f66970+zJ1Lc4mHq07/HHwo", "ripemd160", undefined);

      // Constants table
      var _zl = WordArray.create([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]);
      var _zr = WordArray.create([5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]);
      var _sl = WordArray.create([11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]);
      var _sr = WordArray.create([8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]);
      var _hl = WordArray.create([0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
      var _hr = WordArray.create([0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);
      var f1 = function f1(x, y, z) {
        return x ^ y ^ z;
      };
      var f2 = function f2(x, y, z) {
        return x & y | ~x & z;
      };
      var f3 = function f3(x, y, z) {
        return (x | ~y) ^ z;
      };
      var f4 = function f4(x, y, z) {
        return x & z | y & ~z;
      };
      var f5 = function f5(x, y, z) {
        return x ^ (y | ~z);
      };
      var rotl = function rotl(x, n) {
        return x << n | x >>> 32 - n;
      };

      /**
       * RIPEMD160 hash algorithm.
       */
      var RIPEMD160Algo = exports('RIPEMD160Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(RIPEMD160Algo, _Hasher);
        function RIPEMD160Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = RIPEMD160Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          var _M = M;

          // Swap endian
          for (var i = 0; i < 16; i += 1) {
            // Shortcuts
            var offset_i = offset + i;
            var M_offset_i = _M[offset_i];

            // Swap
            _M[offset_i] = (M_offset_i << 8 | M_offset_i >>> 24) & 0x00ff00ff | (M_offset_i << 24 | M_offset_i >>> 8) & 0xff00ff00;
          }
          // Shortcut
          var H = this._hash.words;
          var hl = _hl.words;
          var hr = _hr.words;
          var zl = _zl.words;
          var zr = _zr.words;
          var sl = _sl.words;
          var sr = _sr.words;

          // Working variables
          var al = H[0];
          var bl = H[1];
          var cl = H[2];
          var dl = H[3];
          var el = H[4];
          var ar = H[0];
          var br = H[1];
          var cr = H[2];
          var dr = H[3];
          var er = H[4];

          // Computation
          var t;
          for (var _i = 0; _i < 80; _i += 1) {
            t = al + _M[offset + zl[_i]] | 0;
            if (_i < 16) {
              t += f1(bl, cl, dl) + hl[0];
            } else if (_i < 32) {
              t += f2(bl, cl, dl) + hl[1];
            } else if (_i < 48) {
              t += f3(bl, cl, dl) + hl[2];
            } else if (_i < 64) {
              t += f4(bl, cl, dl) + hl[3];
            } else {
              // if (i<80) {
              t += f5(bl, cl, dl) + hl[4];
            }
            t |= 0;
            t = rotl(t, sl[_i]);
            t = t + el | 0;
            al = el;
            el = dl;
            dl = rotl(cl, 10);
            cl = bl;
            bl = t;
            t = ar + _M[offset + zr[_i]] | 0;
            if (_i < 16) {
              t += f5(br, cr, dr) + hr[0];
            } else if (_i < 32) {
              t += f4(br, cr, dr) + hr[1];
            } else if (_i < 48) {
              t += f3(br, cr, dr) + hr[2];
            } else if (_i < 64) {
              t += f2(br, cr, dr) + hr[3];
            } else {
              // if (i<80) {
              t += f1(br, cr, dr) + hr[4];
            }
            t |= 0;
            t = rotl(t, sr[_i]);
            t = t + er | 0;
            ar = er;
            er = dr;
            dr = rotl(cr, 10);
            cr = br;
            br = t;
          }
          // Intermediate hash value
          t = H[1] + cl + dr | 0;
          H[1] = H[2] + dl + er | 0;
          H[2] = H[3] + el + ar | 0;
          H[3] = H[4] + al + br | 0;
          H[4] = H[0] + bl + cr | 0;
          H[0] = t;
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = (nBitsTotal << 8 | nBitsTotal >>> 24) & 0x00ff00ff | (nBitsTotal << 24 | nBitsTotal >>> 8) & 0xff00ff00;
          data.sigBytes = (dataWords.length + 1) * 4;

          // Hash final blocks
          this._process();

          // Shortcuts
          var hash = this._hash;
          var H = hash.words;

          // Swap endian
          for (var i = 0; i < 5; i += 1) {
            // Shortcut
            var H_i = H[i];

            // Swap
            H[i] = (H_i << 8 | H_i >>> 24) & 0x00ff00ff | (H_i << 24 | H_i >>> 8) & 0xff00ff00;
          }

          // Return final computed hash
          return hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return RIPEMD160Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.RIPEMD160('message');
       *     var hash = CryptoJS.RIPEMD160(wordArray);
       */
      var RIPEMD160 = exports('RIPEMD160', Hasher._createHelper(RIPEMD160Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
       */
      var HmacRIPEMD160 = exports('HmacRIPEMD160', Hasher._createHmacHelper(RIPEMD160Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ScreenAdapter.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './EventMng.ts', './GameContorl.ts', './BasicEnum.ts', './CommonValue.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _asyncToGenerator, _regeneratorRuntime, cclegacy, _decorator, Prefab, sys, view, macro, screen, instantiate, Canvas, director, ResolutionPolicy, Component, EventMng, NotificationType, GameContorl, Platform, BasicEnum, CommonValue;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Prefab = module.Prefab;
      sys = module.sys;
      view = module.view;
      macro = module.macro;
      screen = module.screen;
      instantiate = module.instantiate;
      Canvas = module.Canvas;
      director = module.director;
      ResolutionPolicy = module.ResolutionPolicy;
      Component = module.Component;
    }, function (module) {
      EventMng = module.default;
      NotificationType = module.NotificationType;
    }, function (module) {
      GameContorl = module.default;
    }, function (module) {
      Platform = module.Platform;
      BasicEnum = module.BasicEnum;
    }, function (module) {
      CommonValue = module.default;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _class, _class2, _descriptor;
      cclegacy._RF.push({}, "7fc18rp52RD7I4ftX59Vnus", "ScreenAdapter", undefined);
      var ccclass = _decorator.ccclass,
        executionOrder = _decorator.executionOrder,
        help = _decorator.help,
        menu = _decorator.menu,
        property = _decorator.property;

      /**
       * 屏幕适配组件
       * @author 陈皮皮 (ifaswind)
       * @version 20210504
       * @see ScreenAdapter.ts https://gitee.com/ifaswind/eazax-ccc/blob/master/components/ScreenAdapter.ts
       */
      var ScreenAdapter = exports('default', (_dec = executionOrder(-1), _dec2 = help('https://gitee.com/ifaswind/eazax-ccc/blob/master/components/ScreenAdapter.ts'), _dec3 = menu('eazax/其他组件/ScreenAdapter'), _dec4 = property(Prefab), ccclass(_class = _dec(_class = _dec2(_class = _dec3(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(ScreenAdapter, _Component);
        function ScreenAdapter() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _this.timer = 0;
          _this.isInit = void 0;
          _initializerDefineProperty(_this, "canvasPrefab", _descriptor, _assertThisInitialized(_this));
          _this.canvas = void 0;
          _this.isCanUpdata = true;
          return _this;
        }
        var _proto = ScreenAdapter.prototype;
        /**
         * 生命周期：加载
         */
        _proto.onLoad = function onLoad() {
          console.log("是不是手機", sys.isMobile);
          if (sys.isMobile) {
            //手機只做直視不做自適應
            view.setOrientation(macro.ORIENTATION_PORTRAIT);
            view.resizeWithBrowserSize(false);
            return;
          } else view.setOrientation(macro.ORIENTATION_AUTO);
          window.addEventListener("message", this.onReceiveMessage.bind(this), false);
          screen.on('window-resize', this.onResize, this);
        };
        _proto.start = function start() {
          var _this2 = this;
          var temp = setInterval(function () {
            if (GameContorl.instance.isPrefabLoad) {
              _this2.onResize();
              clearInterval(temp);
            }
          }, 16);
        };
        _proto.onReceiveMessage = function onReceiveMessage(event) {
          this.onResize();
        }

        /**
         * 窗口变化回调
         */;
        _proto.onResize = /*#__PURE__*/
        function () {
          var _onResize = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee() {
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  // if (this.isCanUpdata) {
                  //     this.isCanUpdata = false
                  //     setTimeout(async () => {
                  GameContorl.instance.moveBase();
                  _context.next = 3;
                  return this.reset();
                case 3:
                  this.scheduleOnce(this.adapt_forDesktop.bind(this), 0);

                //     }, 300);
                // }
                // else {
                //     console.error("等待刷新......");
                // }
                case 4:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function onResize() {
            return _onResize.apply(this, arguments);
          }
          return onResize;
        }();
        _proto.reset = function reset() {
          var _this3 = this;
          if (this.canvas) this.canvas.node.destroy();
          return new Promise(function (resolve, reject) {
            _this3.canvas = instantiate(_this3.canvasPrefab).getComponent(Canvas);
            _this3.canvas.node.setParent(director.getScene());
            resolve();
          });
        };
        _proto.adapt_forDesktop = function adapt_forDesktop() {
          var winSize = screen.windowSize;
          if (winSize.width > winSize.height) {
            view.setDesignResolutionSize(1920, 1080, ResolutionPolicy.SHOW_ALL);
            if (CommonValue.platform != Platform.Web) {
              CommonValue.platform = Platform.Web;
            }
            this.canvas.cameraComponent.orthoHeight = 540;
            EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, true);
          } else {
            view.setDesignResolutionSize(1080, 1920, ResolutionPolicy.SHOW_ALL);
            if (CommonValue.platform != Platform.Mobile) {
              CommonValue.platform = Platform.Mobile;
            }
            EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, false);
          }
          GameContorl.instance.setPanelIndex();

          // if (this.canvas) {
          //     if (!sys.isMobile)
          // if (!this.isInit) {

          //     if (this.canvas.cameraComponent.orthoHeight > (2338 / 2)) {
          //         this.canvas.cameraComponent.orthoHeight = (this.canvas.cameraComponent.orthoHeight / 2) * 1.1
          //         if (this.canvas.cameraComponent.orthoHeight < 2338 / 2)
          //             this.canvas.cameraComponent.orthoHeight = 2338 / 2
          //     }
          //     this.isInit = true
          // }
          console.log(this.canvas.cameraComponent.orthoHeight);
          // this.isCanUpdata = true
          // }
        };

        _proto.adapt_v4 = function adapt_v4() {
          var _this4 = this;
          //高度極限707
          var visibleSize = view.getVisibleSize();
          var designSize = view.getDesignResolutionSize();
          var aspectRatioVisible = visibleSize.height / visibleSize.width;
          var aspectRatioDesign = designSize.height / designSize.width;
          // Define thresholds for aspect ratios close to 3:4 (0.75) or 4:3 (1.33)
          var lowerThreshold = 0.7;
          var upperThreshold = 1.4;
          // Check if the aspect ratio is within the "close to square" range
          var isCloseToSquare = aspectRatioVisible >= lowerThreshold && aspectRatioVisible <= upperThreshold;
          console.error(isCloseToSquare);
          if (isCloseToSquare) {
            var winSize = screen.windowSize;
            // Use SHOW_ALL for aspect ratios close to square
            if (winSize.width > 840) {
              // if (winSize.height > winSize.width) {
              view.setDesignResolutionSize(1920, 1080, ResolutionPolicy.SHOW_ALL);
              if (CommonValue.platform != Platform.Web) {
                CommonValue.platform = Platform.Web;
              }
              EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, true);
            } else {
              view.setDesignResolutionSize(1080, 1920, ResolutionPolicy.SHOW_ALL);
              if (CommonValue.platform != Platform.Mobile) {
                CommonValue.platform = Platform.Mobile;
              }
              EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, false);
            }
            // view.setDesignResolutionSize(designSize.width, designSize.height, ResolutionPolicy.SHOW_ALL);
            // CommonValue.platform = Platform.Mobile;
            // EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, false);
            // EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, null);
          } else if (aspectRatioVisible > aspectRatioDesign) {
            // Long screen (portrait)
            if (designSize.width != 1080) {
              view.setDesignResolutionSize(1080, 1920, ResolutionPolicy.FIXED_WIDTH);
            } else {
              view.setDesignResolutionSize(designSize.width, designSize.height, ResolutionPolicy.FIXED_WIDTH);
            }
            CommonValue.platform = Platform.Mobile;
            EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, false);
          } else {
            // Wide screen (landscape)
            console.log(designSize);
            if (designSize.height != 1080) {
              view.setDesignResolutionSize(1920, 1080, ResolutionPolicy.FIXED_HEIGHT);
            } else {
              view.setDesignResolutionSize(designSize.width, designSize.height, ResolutionPolicy.FIXED_HEIGHT);
            }
            CommonValue.platform = Platform.Web;
            EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, true);
          }
          if (!this.isInit) {
            this.scheduleOnce(function (X) {
              return _this4.scheduleOnce(function (x) {
                return window.dispatchEvent(new Event("window-resize"));
              }, 0);
            }, 0);
            instantiate(this.canvasPrefab).setParent(director.getScene());
            this.isInit = true;
          }
        };
        _proto.adapt_v3 = function adapt_v3() {
          var _this5 = this;
          var visibleSize = view.getVisibleSize();
          var designSize = view.getDesignResolutionSize();
          // console.log(visibleSize.height, visibleSize.width);
          // console.log(visibleSize.height / visibleSize.width);
          // console.log(designSize.height, designSize.width);
          // console.log(designSize.height / designSize.width);
          // console.log((visibleSize.height / visibleSize.width).toFixed(3).slice(0, -1));
          // console.log((visibleSize.height / visibleSize.width).toFixed(3).slice(0, -1));
          // console.log((designSize.height / designSize.width).toFixed(3).slice(0, -1));
          var rotaVis = (visibleSize.height / visibleSize.width).toFixed(3).slice(0, -1);
          var rotadesi = (designSize.height / designSize.width).toFixed(3).slice(0, -1);
          // const winSize = view.getFrameSize()
          // console.log(rotadesi, rotaVis);

          if (visibleSize.height / visibleSize.width > designSize.height / designSize.width) {
            // 长屏
            if (designSize.width != 1080) view.setDesignResolutionSize(1080, 1920, ResolutionPolicy.FIXED_WIDTH);else view.setDesignResolutionSize(designSize.width, designSize.height, ResolutionPolicy.FIXED_WIDTH);
            if (CommonValue.platform != Platform.Mobile) {
              CommonValue.platform = Platform.Mobile;
            }
            EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, false);
          } else {
            // 宽屏
            if (designSize.height != 1080) view.setDesignResolutionSize(1920, 1080, ResolutionPolicy.FIXED_HEIGHT);else view.setDesignResolutionSize(designSize.width, designSize.height, ResolutionPolicy.FIXED_HEIGHT);
            if (CommonValue.platform != Platform.Web) {
              CommonValue.platform = Platform.Web;
            }
            EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, true);
          }
          if (!this.isInit) {
            instantiate(this.canvasPrefab).setParent(director.getScene());
            this.scheduleOnce(function (X) {
              return _this5.scheduleOnce(function (x) {
                return window.dispatchEvent(new Event("window-resize"));
              }, 0);
            }, 0);
            this.isInit = true;
          }
        };
        _proto.adapt_v2 = function adapt_v2() {
          var _this6 = this;
          var winSize = screen.windowSize;
          var ratio = winSize.width > 840 ? 16 / 9 : 9 / 16;
          if (winSize.width > 840) {
            // if (winSize.height > winSize.width) {
            view.setDesignResolutionSize(1920, 1080, ResolutionPolicy.FIXED_HEIGHT);
            if (CommonValue.platform != Platform.Web) {
              CommonValue.platform = Platform.Web;
            }
            EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, true);
          } else {
            view.setDesignResolutionSize(1080, 1920, ResolutionPolicy.FIXED_WIDTH);
            if (CommonValue.platform != Platform.Mobile) {
              CommonValue.platform = Platform.Mobile;
            }
            EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, false);
          }
          if (!this.isInit) {
            instantiate(this.canvasPrefab).setParent(director.getScene());
            this.scheduleOnce(function (X) {
              return _this6.scheduleOnce(function (x) {
                return window.dispatchEvent(new Event("window-resize"));
              }, 0);
            }, 0);
            this.isInit = true;
          }
        }

        /**
         * 适配
         */;
        _proto.adapt_v1 = function adapt_v1() {
          // 实际屏幕比例
          var winSize = view.getFrameSize(),
            screenRatio = winSize.width / winSize.height;
          // 设计比例
          var designResolution = view.getDesignResolutionSize(),
            designRatio = designResolution.width / designResolution.height;
          console.log(winSize);
          var ratio = winSize.width > 840 ? 16 / 9 : 9 / 16;
          if (winSize.width / winSize.height > ratio) {
            this.setFitWidth(ratio);
          } else {
            this.setFitHeight(ratio);
          }
          if (screenRatio <= 1) {
            // 此时屏幕高度大于宽度
            if (screenRatio <= designRatio) {
              this.setFitWidth(screenRatio);
            } else {
              // 此时实际屏幕比例大于设计比例
              // 为了保证纵向的游戏内容不受影响，应使用 fitHeight 模式
              this.setFitHeight();
            }
          } else {
            // 此时屏幕高度小于宽度
            this.setFitHeight();
            // }
          }
        };

        _proto.getWinSize = function getWinSize() {
          return {
            width: window.innerWidth,
            height: window.innerHeight
          };
        }

        /**
         * 适配高度模式
         */;
        _proto.setFitHeight = function setFitHeight(ratio) {
          console.warn("H");
          view.setDesignResolutionSize(1920, 1080, ResolutionPolicy.FIXED_HEIGHT);
          EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, true);
          console.log(view.getDesignResolutionSize());
          console.log(view.getResolutionPolicy());
          console.log(view.getViewportRect());
          console.log(view.getVisibleSize());
          console.log(view.getVisibleOrigin());
        }
        /**
         * 适配宽度模式
         */;
        _proto.setFitWidth = function setFitWidth(ratio) {
          // console.log("W");
          view.setDesignResolutionSize(1080, 1920, ResolutionPolicy.FIXED_WIDTH);
          EventMng.getInstance.emit(NotificationType.Basic, BasicEnum.OrientationChange, false);
          // this.canvas.fitHeight = false;
          // this.canvas.fitWidth = true;
        };

        return ScreenAdapter;
      }(Component), _descriptor = _applyDecoratedDescriptor(_class2.prototype, "canvasPrefab", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _class2)) || _class) || _class) || _class) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ScrollViewEvent.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "a0551tttsRI6Y1I7NH/S+7v", "ScrollViewEvent", undefined);
      var ScrollViewEvent = exports('ScrollViewEvent', /*#__PURE__*/function (ScrollViewEvent) {
        ScrollViewEvent["setShowRange"] = "setShowRange";
        ScrollViewEvent["checkItemVisible"] = "checkItemVisible";
        return ScrollViewEvent;
      }({}));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/ScrollViewOnlyShowItemsInMaskRange.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './AutoFollow.ts', './EventMng.ts', './ScrollViewEvent.ts'], function () {
  var _inheritsLoose, cclegacy, _decorator, find, Layout, Mask, UITransform, Sprite, Label, ScrollView, TheTarget, EventMng, NotificationType, ScrollViewEvent;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      find = module.find;
      Layout = module.Layout;
      Mask = module.Mask;
      UITransform = module.UITransform;
      Sprite = module.Sprite;
      Label = module.Label;
      ScrollView = module.ScrollView;
    }, function (module) {
      TheTarget = module.TheTarget;
    }, function (module) {
      EventMng = module.default;
      NotificationType = module.NotificationType;
    }, function (module) {
      ScrollViewEvent = module.ScrollViewEvent;
    }],
    execute: function () {
      var _dec, _dec2, _class;
      cclegacy._RF.push({}, "b826334dW5MBr0lPaukVZLl", "ScrollViewOnlyShowItemsInMaskRange", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property,
        menu = _decorator.menu;
      var ScrollViewOnlyShowItemsInMaskRange = (_dec = ccclass('ScrollViewOnlyShowItemsInMaskRange'), _dec2 = menu('ScrollViewOnlyShowItemsInMaskRange'), _dec(_class = _dec2(_class = /*#__PURE__*/function (_ScrollView) {
        _inheritsLoose(ScrollViewOnlyShowItemsInMaskRange, _ScrollView);
        function ScrollViewOnlyShowItemsInMaskRange() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _ScrollView.call.apply(_ScrollView, [this].concat(args)) || this;
          _this.minX = void 0;
          _this.maxX = void 0;
          _this.minY = void 0;
          _this.maxY = void 0;
          _this.mask = void 0;
          _this.targets = [];
          _this.sprites = [];
          _this.labels = [];
          _this.layout = void 0;
          _this.spriteTran = [];
          _this.labelTran = [];
          _this.targetTran = [];
          _this.viewRange = 100;
          return _this;
        }
        var _proto = ScrollViewOnlyShowItemsInMaskRange.prototype;
        _proto.onLoad = function onLoad() {
          EventMng.getInstance.setEvent(NotificationType.ScrollView, ScrollViewEvent.setShowRange, this.setShowRange, this);
          EventMng.getInstance.setEvent(NotificationType.ScrollView, ScrollViewEvent.checkItemVisible, this.refreshItemCompent, this);
          this.mask = find("Mask", this.node);
          this.layout = this.content.getComponent(Layout);
        };
        _proto.start = function start() {
          _ScrollView.prototype.start.call(this);
          this.setShowRange();
          this.refreshItemCompent();
        };
        _proto.setShowRange = function setShowRange() {
          var viewNode = this.node;
          if (this.mask) viewNode = this.node.getComponentInChildren(Mask).node;
          var uiTransform = viewNode.getComponent(UITransform);
          this.minX = viewNode.getWorldPosition().x - this.viewRange - uiTransform.contentSize.width * uiTransform.anchorPoint.x;
          this.maxX = viewNode.getWorldPosition().x + this.viewRange + uiTransform.contentSize.width * (1 - uiTransform.anchorPoint.x);
          this.minY = viewNode.getWorldPosition().y - this.viewRange - uiTransform.contentSize.height * uiTransform.anchorPoint.y;
          this.maxY = viewNode.getWorldPosition().y + this.viewRange + uiTransform.contentSize.height * (1 - uiTransform.anchorPoint.y);
          // warn(this.node.parent.name, this.minX, this.maxX, this.minY, this.maxY)
        };

        _proto.checkItemVisible = function checkItemVisible() {
          this.layout.updateLayout();
          for (var i = 0; i < this.content.children.length; i++) {
            if (this.horizontal) {
              if (this.sprites[i]) for (var j = 0; j < this.sprites[i].length; j++) {
                if (!this.sprites[i][j].node) continue;
                var width = this.spriteTran[j].width;
                var anchorX = this.spriteTran[j].anchorX;
                var posL = this.sprites[i][j].node.getWorldPosition().x - width * anchorX;
                var posR = this.sprites[i][j].node.getWorldPosition().x + width * (1 - anchorX);
                if (posR >= this.minX && posL <= this.maxX) this.sprites[i][j].enabled = true;else this.sprites[i][j].enabled = false;
              }
              if (this.labels[i]) for (var _j = 0; _j < this.labels[i].length; _j++) {
                if (!this.labels[i][_j].node) continue;
                var _width = this.labelTran[_j].width;
                var _anchorX = this.labelTran[_j].anchorX;
                var _posL = this.labels[i][_j].node.getWorldPosition().x - _width * _anchorX;
                var _posR = this.labels[i][_j].node.getWorldPosition().x + _width * (1 - _anchorX);
                if (_posR >= this.minX && _posL <= this.maxX) this.labels[i][_j].enabled = true;else this.labels[i][_j].enabled = false;
              }
              if (this.targets[i]) for (var _j2 = 0; _j2 < this.targets[i].length; _j2++) {
                if (!this.targets[i][_j2].node) continue;
                var _width2 = this.targetTran[_j2].width;
                var _anchorX2 = this.targetTran[_j2].anchorX;
                var _posL2 = this.targets[i][_j2].node.getWorldPosition().x - _width2 * _anchorX2;
                var _posR2 = this.targets[i][_j2].node.getWorldPosition().x + _width2 * (1 - _anchorX2);
                if (_posR2 >= this.minX && _posL2 <= this.maxX) this.targets[i][_j2].isCanSee = true;else this.targets[i][_j2].isCanSee = false;
              }
            } else {
              if (this.sprites[i]) for (var _j3 = 0; _j3 < this.sprites[i].length; _j3++) {
                if (!this.sprites[i][_j3].node) continue;
                var height = this.spriteTran[_j3].height;
                var anchorY = this.spriteTran[_j3].anchorY;
                var posB = this.sprites[i][_j3].node.getWorldPosition().y - height * anchorY;
                var posT = this.sprites[i][_j3].node.getWorldPosition().y + height * (1 - anchorY);
                if (posT >= this.minY && posB <= this.maxY) this.sprites[i][_j3].enabled = true;else this.sprites[i][_j3].enabled = false;
              }
              if (this.labels[i]) for (var _j4 = 0; _j4 < this.labels[i].length; _j4++) {
                if (!this.labels[i][_j4].node) continue;
                var _height = this.labelTran[_j4].height;
                var _anchorY = this.labelTran[_j4].anchorY;
                var _posB = this.labels[i][_j4].node.getWorldPosition().y - _height * _anchorY;
                var _posT = this.labels[i][_j4].node.getWorldPosition().y + _height * (1 - _anchorY);
                if (_posT >= this.minY && _posB <= this.maxY) this.labels[i][_j4].enabled = true;else this.labels[i][_j4].enabled = false;
              }
              if (this.targets[i]) for (var _j5 = 0; _j5 < this.targets[i].length; _j5++) {
                if (!this.targets[i][_j5].node) continue;
                var _height2 = this.targetTran[_j5].height;
                var _anchorY2 = this.targetTran[_j5].anchorY;
                var _posB2 = this.targets[i][_j5].node.getWorldPosition().y - _height2 * _anchorY2;
                var _posT2 = this.targets[i][_j5].node.getWorldPosition().y + _height2 * (1 - _anchorY2);
                if (_posT2 >= this.minY && _posB2 <= this.maxY) this.targets[i][_j5].isCanSee = true;else this.targets[i][_j5].isCanSee = false;
              }
            }
          }
          // EventMng.getInstance.emit(NotificationType.ScrollView, ScrollViewEvent.resetDynamicAtlas)
        };

        _proto.update = function update(dt) {
          var _this2 = this;
          _ScrollView.prototype.update.call(this, dt);
          var pos0 = this.content.getPosition();
          this.scheduleOnce(function () {
            if (_this2.content && (pos0.x != _this2.content.getPosition().x || pos0.y != _this2.content.getPosition().y)) _this2.checkItemVisible();
          }, 0);
        };
        _proto.onDestroy = function onDestroy() {
          EventMng.getInstance.deletEvent(NotificationType.ScrollView, ScrollViewEvent.setShowRange, this.setShowRange, this);
          EventMng.getInstance.deletEvent(NotificationType.ScrollView, ScrollViewEvent.checkItemVisible, this.refreshItemCompent, this);
        };
        _proto.refreshItemCompent = function refreshItemCompent() {
          this.targets = [];
          this.sprites = [];
          this.labels = [];
          this.targetTran = [];
          this.spriteTran = [];
          this.labelTran = [];
          for (var i = 0; i < this.content.children.length; i++) {
            this.targets.push(this.content.children[i].getComponentsInChildren(TheTarget));
            this.sprites.push(this.content.children[i].getComponentsInChildren(Sprite));
            this.labels.push(this.content.children[i].getComponentsInChildren(Label));
            for (var j = 0; j < this.targets[i].length; j++) {
              this.targetTran.push(this.targets[i][j].node.getComponent(UITransform));
            }
            for (var _j6 = 0; _j6 < this.sprites[i].length; _j6++) {
              this.spriteTran.push(this.sprites[i][_j6].node.getComponent(UITransform));
            }
            for (var _j7 = 0; _j7 < this.labels[i].length; _j7++) {
              this.labelTran.push(this.labels[i][_j7].node.getComponent(UITransform));
            }
          }
          this.checkItemVisible();
        };
        return ScrollViewOnlyShowItemsInMaskRange;
      }(ScrollView)) || _class) || _class);
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/secs.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "577a2Ki/tJKkYRwKp2WXrEO", "secs", undefined);
      var minute = 60;
      var hour = minute * 60;
      var day = hour * 24;
      var week = day * 7;
      var year = day * 365.25;
      var REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
      var secs = exports('default', function (str) {
        var matched = REGEX.exec(str);
        if (!matched || matched[4] && matched[1]) {
          throw new TypeError('Invalid time period format');
        }
        var value = parseFloat(matched[2]);
        var unit = matched[3].toLowerCase();
        var numericDate;
        switch (unit) {
          case 'sec':
          case 'secs':
          case 'second':
          case 'seconds':
          case 's':
            numericDate = Math.round(value);
            break;
          case 'minute':
          case 'minutes':
          case 'min':
          case 'mins':
          case 'm':
            numericDate = Math.round(value * minute);
            break;
          case 'hour':
          case 'hours':
          case 'hr':
          case 'hrs':
          case 'h':
            numericDate = Math.round(value * hour);
            break;
          case 'day':
          case 'days':
          case 'd':
            numericDate = Math.round(value * day);
            break;
          case 'week':
          case 'weeks':
          case 'w':
            numericDate = Math.round(value * week);
            break;
          // years matched
          default:
            numericDate = Math.round(value * year);
            break;
        }
        if (matched[1] === '-' || matched[4] === 'ago') {
          return -numericDate;
        }
        return numericDate;
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/SetBtnEventForKeepTouching.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _inheritsLoose, cclegacy, Node, Component;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      Node = module.Node;
      Component = module.Component;
    }],
    execute: function () {
      cclegacy._RF.push({}, "dec07T9WRVN3bkfgmhXKY00", "SetBtnEventForKeepTouching", undefined);
      var SetBtnEventForKeepTouching = exports('SetBtnEventForKeepTouching', /*#__PURE__*/function (_Component) {
        _inheritsLoose(SetBtnEventForKeepTouching, _Component);
        function SetBtnEventForKeepTouching() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _this.touchFlag = void 0;
          _this.touchStartTime = void 0;
          _this.touchingEvent = void 0;
          _this.event = void 0;
          /**最長冷卻 */
          _this.LongestCD = 200;
          /**最短冷卻 */
          _this.shortestCD = 50;
          /**遞增速率 */
          _this.acc = 10;
          return _this;
        }
        var _proto = SetBtnEventForKeepTouching.prototype;
        _proto.onLoad = function onLoad() {
          //声明触摸时间变量
          this.touchFlag = false;
          this.touchStartTime = null;
          //添加按钮触摸监听 长按弹托管弹窗列表
          this.node.on(Node.EventType.TOUCH_START, this.touchStart, this);
          this.node.on(Node.EventType.TOUCH_END, this.touchEnd, this);
          this.node.on(Node.EventType.TOUCH_CANCEL, this.touchEnd, this);
        };
        _proto.touchStart = function touchStart(e) {
          this.event = e;
          this.touchingEvent(e);
          this.LongestCD = 200;

          //触摸开始 
          this.touchFlag = true;
          //记录下触摸开始时间
          this.touchStartTime = new Date();
        }
        //触摸结束
        ;

        _proto.touchEnd = function touchEnd() {
          this.touchFlag = false;
          this.touchStartTime = null;
          //出发单击事务逻辑
          //todo...
        }
        //长按检测函数
        ;

        _proto.touchHold = function touchHold() {
          if (this.touchFlag && this.touchStartTime != null) {
            //判断按钮的按压时长
            var touchHoldTime = new Date();
            var milliseconds = touchHoldTime.getTime() - this.touchStartTime.getTime();
            // warn(milliseconds)
            if (milliseconds > this.LongestCD) {
              this.touchStartTime = new Date();
              if (this.LongestCD > this.shortestCD) this.LongestCD -= this.acc;
              //触发托管事务逻辑 
              this.touchingEvent(this.event);
              //todo...
            }
          }
        };

        _proto.update = function update(dt) {
          //判断是否检测按钮长按状态
          if (this.touchFlag) {
            this.touchHold();
          }
        };
        _proto.setAction = function setAction(event) {
          this.touchingEvent = event;
        };
        return SetBtnEventForKeepTouching;
      }(Component));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sha1.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, Hasher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
      Hasher = module.Hasher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "25417LKYAZCVL6Tnldwn5hx", "sha1", undefined);

      // Reusable object
      var W = [];

      /**
       * SHA-1 hash algorithm.
       */
      var SHA1Algo = exports('SHA1Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(SHA1Algo, _Hasher);
        function SHA1Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = SHA1Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          // Shortcut
          var H = this._hash.words;

          // Working variables
          var a = H[0];
          var b = H[1];
          var c = H[2];
          var d = H[3];
          var e = H[4];

          // Computation
          for (var i = 0; i < 80; i += 1) {
            if (i < 16) {
              W[i] = M[offset + i] | 0;
            } else {
              var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
              W[i] = n << 1 | n >>> 31;
            }
            var t = (a << 5 | a >>> 27) + e + W[i];
            if (i < 20) {
              t += (b & c | ~b & d) + 0x5a827999;
            } else if (i < 40) {
              t += (b ^ c ^ d) + 0x6ed9eba1;
            } else if (i < 60) {
              t += (b & c | b & d | c & d) - 0x70e44324;
            } else /* if (i < 80) */{
                t += (b ^ c ^ d) - 0x359d3e2a;
              }
            e = d;
            d = c;
            c = b << 30 | b >>> 2;
            b = a;
            a = t;
          }

          // Intermediate hash value
          H[0] = H[0] + a | 0;
          H[1] = H[1] + b | 0;
          H[2] = H[2] + c | 0;
          H[3] = H[3] + d | 0;
          H[4] = H[4] + e | 0;
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 15] = nBitsTotal;
          data.sigBytes = dataWords.length * 4;

          // Hash final blocks
          this._process();

          // Return final computed hash
          return this._hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return SHA1Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA1('message');
       *     var hash = CryptoJS.SHA1(wordArray);
       */
      var SHA1 = exports('SHA1', Hasher._createHelper(SHA1Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA1(message, key);
       */
      var HmacSHA1 = exports('HmacSHA1', Hasher._createHmacHelper(SHA1Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sha224.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js', './sha256.js'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, SHA256Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
    }, function (module) {
      SHA256Algo = module.SHA256Algo;
    }],
    execute: function () {
      cclegacy._RF.push({}, "1df3bS2xARLc4oSMdVZFdJB", "sha224", undefined);

      /**
       * SHA-224 hash algorithm.
       */
      var SHA224Algo = exports('SHA224Algo', /*#__PURE__*/function (_SHA256Algo) {
        _inheritsLoose(SHA224Algo, _SHA256Algo);
        function SHA224Algo() {
          return _SHA256Algo.apply(this, arguments) || this;
        }
        var _proto = SHA224Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray([0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]);
        };
        _proto._doFinalize = function _doFinalize() {
          var hash = _SHA256Algo.prototype._doFinalize.call(this);
          hash.sigBytes -= 4;
          return hash;
        };
        return SHA224Algo;
      }(SHA256Algo));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA224('message');
       *     var hash = CryptoJS.SHA224(wordArray);
       */
      var SHA224 = exports('SHA224', SHA256Algo._createHelper(SHA224Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA224(message, key);
       */
      var HmacSHA224 = exports('HmacSHA224', SHA256Algo._createHmacHelper(SHA224Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sha256.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, Hasher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
      Hasher = module.Hasher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "33c0c3qRkpGL5Ks/Q6x+eDw", "sha256", undefined);

      // Initialization and round constants tables
      var H = [];
      var K = [];

      // Compute constants
      var isPrime = function isPrime(n) {
        var sqrtN = Math.sqrt(n);
        for (var factor = 2; factor <= sqrtN; factor += 1) {
          if (!(n % factor)) {
            return false;
          }
        }
        return true;
      };
      var getFractionalBits = function getFractionalBits(n) {
        return (n - (n | 0)) * 0x100000000 | 0;
      };
      var n = 2;
      var nPrime = 0;
      while (nPrime < 64) {
        if (isPrime(n)) {
          if (nPrime < 8) {
            H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
          }
          K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));
          nPrime += 1;
        }
        n += 1;
      }

      // Reusable object
      var W = [];

      /**
       * SHA-256 hash algorithm.
       */
      var SHA256Algo = exports('SHA256Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(SHA256Algo, _Hasher);
        function SHA256Algo() {
          return _Hasher.apply(this, arguments) || this;
        }
        var _proto = SHA256Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new WordArray(H.slice(0));
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          // Shortcut
          var _H = this._hash.words;

          // Working variables
          var a = _H[0];
          var b = _H[1];
          var c = _H[2];
          var d = _H[3];
          var e = _H[4];
          var f = _H[5];
          var g = _H[6];
          var h = _H[7];

          // Computation
          for (var i = 0; i < 64; i += 1) {
            if (i < 16) {
              W[i] = M[offset + i] | 0;
            } else {
              var gamma0x = W[i - 15];
              var gamma0 = (gamma0x << 25 | gamma0x >>> 7) ^ (gamma0x << 14 | gamma0x >>> 18) ^ gamma0x >>> 3;
              var gamma1x = W[i - 2];
              var gamma1 = (gamma1x << 15 | gamma1x >>> 17) ^ (gamma1x << 13 | gamma1x >>> 19) ^ gamma1x >>> 10;
              W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
            }
            var ch = e & f ^ ~e & g;
            var maj = a & b ^ a & c ^ b & c;
            var sigma0 = (a << 30 | a >>> 2) ^ (a << 19 | a >>> 13) ^ (a << 10 | a >>> 22);
            var sigma1 = (e << 26 | e >>> 6) ^ (e << 21 | e >>> 11) ^ (e << 7 | e >>> 25);
            var t1 = h + sigma1 + ch + K[i] + W[i];
            var t2 = sigma0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1 | 0;
            d = c;
            c = b;
            b = a;
            a = t1 + t2 | 0;
          }

          // Intermediate hash value
          _H[0] = _H[0] + a | 0;
          _H[1] = _H[1] + b | 0;
          _H[2] = _H[2] + c | 0;
          _H[3] = _H[3] + d | 0;
          _H[4] = _H[4] + e | 0;
          _H[5] = _H[5] + f | 0;
          _H[6] = _H[6] + g | 0;
          _H[7] = _H[7] + h | 0;
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
          dataWords[(nBitsLeft + 64 >>> 9 << 4) + 15] = nBitsTotal;
          data.sigBytes = dataWords.length * 4;

          // Hash final blocks
          this._process();

          // Return final computed hash
          return this._hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return SHA256Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA256('message');
       *     var hash = CryptoJS.SHA256(wordArray);
       */
      var SHA256 = exports('SHA256', Hasher._createHelper(SHA256Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA256(message, key);
       */
      var HmacSHA256 = exports('HmacSHA256', Hasher._createHmacHelper(SHA256Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sha3.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js', './x64-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, Hasher, X64Word;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
      Hasher = module.Hasher;
    }, function (module) {
      X64Word = module.X64Word;
    }],
    execute: function () {
      cclegacy._RF.push({}, "13e12/4lc5Hfrjm7BXHFnkT", "sha3", undefined);

      // Constants tables
      var RHO_OFFSETS = [];
      var PI_INDEXES = [];
      var ROUND_CONSTANTS = [];

      // Compute Constants
      // Compute rho offset constants
      var _x = 1;
      var _y = 0;
      for (var t = 0; t < 24; t += 1) {
        RHO_OFFSETS[_x + 5 * _y] = (t + 1) * (t + 2) / 2 % 64;
        var newX = _y % 5;
        var newY = (2 * _x + 3 * _y) % 5;
        _x = newX;
        _y = newY;
      }

      // Compute pi index constants
      for (var x = 0; x < 5; x += 1) {
        for (var y = 0; y < 5; y += 1) {
          PI_INDEXES[x + 5 * y] = y + (2 * x + 3 * y) % 5 * 5;
        }
      }

      // Compute round constants
      var LFSR = 0x01;
      for (var i = 0; i < 24; i += 1) {
        var roundConstantMsw = 0;
        var roundConstantLsw = 0;
        for (var j = 0; j < 7; j += 1) {
          if (LFSR & 0x01) {
            var bitPosition = (1 << j) - 1;
            if (bitPosition < 32) {
              roundConstantLsw ^= 1 << bitPosition;
            } else /* if (bitPosition >= 32) */{
                roundConstantMsw ^= 1 << bitPosition - 32;
              }
          }

          // Compute next LFSR
          if (LFSR & 0x80) {
            // Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
            LFSR = LFSR << 1 ^ 0x71;
          } else {
            LFSR <<= 1;
          }
        }
        ROUND_CONSTANTS[i] = X64Word.create(roundConstantMsw, roundConstantLsw);
      }

      // Reusable objects for temporary values
      var T = [];
      for (var _i = 0; _i < 25; _i += 1) {
        T[_i] = X64Word.create();
      }

      /**
       * SHA-3 hash algorithm.
       */
      var SHA3Algo = exports('SHA3Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(SHA3Algo, _Hasher);
        function SHA3Algo(cfg) {
          /**
           * Configuration options.
           *
           * @property {number} outputLength
           *   The desired number of bits in the output hash.
           *   Only values permitted are: 224, 256, 384, 512.
           *   Default: 512
           */
          return _Hasher.call(this, Object.assign({
            outputLength: 512
          }, cfg)) || this;
        }
        var _proto = SHA3Algo.prototype;
        _proto._doReset = function _doReset() {
          this._state = [];
          var state = this._state;
          for (var _i2 = 0; _i2 < 25; _i2 += 1) {
            state[_i2] = new X64Word();
          }
          this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          // Shortcuts
          var state = this._state;
          var nBlockSizeLanes = this.blockSize / 2;

          // Absorb
          for (var _i3 = 0; _i3 < nBlockSizeLanes; _i3 += 1) {
            // Shortcuts
            var M2i = M[offset + 2 * _i3];
            var M2i1 = M[offset + 2 * _i3 + 1];

            // Swap endian
            M2i = (M2i << 8 | M2i >>> 24) & 0x00ff00ff | (M2i << 24 | M2i >>> 8) & 0xff00ff00;
            M2i1 = (M2i1 << 8 | M2i1 >>> 24) & 0x00ff00ff | (M2i1 << 24 | M2i1 >>> 8) & 0xff00ff00;

            // Absorb message into state
            var lane = state[_i3];
            lane.high ^= M2i1;
            lane.low ^= M2i;
          }

          // Rounds
          for (var round = 0; round < 24; round += 1) {
            // Theta
            for (var _x2 = 0; _x2 < 5; _x2 += 1) {
              // Mix column lanes
              var tMsw = 0;
              var tLsw = 0;
              for (var _y2 = 0; _y2 < 5; _y2 += 1) {
                var _lane = state[_x2 + 5 * _y2];
                tMsw ^= _lane.high;
                tLsw ^= _lane.low;
              }

              // Temporary values
              var Tx = T[_x2];
              Tx.high = tMsw;
              Tx.low = tLsw;
            }
            for (var _x3 = 0; _x3 < 5; _x3 += 1) {
              // Shortcuts
              var Tx4 = T[(_x3 + 4) % 5];
              var Tx1 = T[(_x3 + 1) % 5];
              var Tx1Msw = Tx1.high;
              var Tx1Lsw = Tx1.low;

              // Mix surrounding columns
              var _tMsw = Tx4.high ^ (Tx1Msw << 1 | Tx1Lsw >>> 31);
              var _tLsw = Tx4.low ^ (Tx1Lsw << 1 | Tx1Msw >>> 31);
              for (var _y3 = 0; _y3 < 5; _y3 += 1) {
                var _lane2 = state[_x3 + 5 * _y3];
                _lane2.high ^= _tMsw;
                _lane2.low ^= _tLsw;
              }
            }

            // Rho Pi
            for (var laneIndex = 1; laneIndex < 25; laneIndex += 1) {
              var _tMsw2 = void 0;
              var _tLsw2 = void 0;

              // Shortcuts
              var _lane3 = state[laneIndex];
              var laneMsw = _lane3.high;
              var laneLsw = _lane3.low;
              var rhoOffset = RHO_OFFSETS[laneIndex];

              // Rotate lanes
              if (rhoOffset < 32) {
                _tMsw2 = laneMsw << rhoOffset | laneLsw >>> 32 - rhoOffset;
                _tLsw2 = laneLsw << rhoOffset | laneMsw >>> 32 - rhoOffset;
              } else /* if (rhoOffset >= 32) */{
                  _tMsw2 = laneLsw << rhoOffset - 32 | laneMsw >>> 64 - rhoOffset;
                  _tLsw2 = laneMsw << rhoOffset - 32 | laneLsw >>> 64 - rhoOffset;
                }

              // Transpose lanes
              var TPiLane = T[PI_INDEXES[laneIndex]];
              TPiLane.high = _tMsw2;
              TPiLane.low = _tLsw2;
            }

            // Rho pi at x = y = 0
            var T0 = T[0];
            var state0 = state[0];
            T0.high = state0.high;
            T0.low = state0.low;

            // Chi
            for (var _x4 = 0; _x4 < 5; _x4 += 1) {
              for (var _y4 = 0; _y4 < 5; _y4 += 1) {
                // Shortcuts
                var _laneIndex = _x4 + 5 * _y4;
                var _lane4 = state[_laneIndex];
                var TLane = T[_laneIndex];
                var Tx1Lane = T[(_x4 + 1) % 5 + 5 * _y4];
                var Tx2Lane = T[(_x4 + 2) % 5 + 5 * _y4];

                // Mix rows
                _lane4.high = TLane.high ^ ~Tx1Lane.high & Tx2Lane.high;
                _lane4.low = TLane.low ^ ~Tx1Lane.low & Tx2Lane.low;
              }
            }

            // Iota
            var _lane5 = state[0];
            var roundConstant = ROUND_CONSTANTS[round];
            _lane5.high ^= roundConstant.high;
            _lane5.low ^= roundConstant.low;
          }
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsLeft = data.sigBytes * 8;
          var blockSizeBits = this.blockSize * 32;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x1 << 24 - nBitsLeft % 32;
          dataWords[(Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits >>> 5) - 1] |= 0x80;
          data.sigBytes = dataWords.length * 4;

          // Hash final blocks
          this._process();

          // Shortcuts
          var state = this._state;
          var outputLengthBytes = this.cfg.outputLength / 8;
          var outputLengthLanes = outputLengthBytes / 8;

          // Squeeze
          var hashWords = [];
          for (var _i4 = 0; _i4 < outputLengthLanes; _i4 += 1) {
            // Shortcuts
            var lane = state[_i4];
            var laneMsw = lane.high;
            var laneLsw = lane.low;

            // Swap endian
            laneMsw = (laneMsw << 8 | laneMsw >>> 24) & 0x00ff00ff | (laneMsw << 24 | laneMsw >>> 8) & 0xff00ff00;
            laneLsw = (laneLsw << 8 | laneLsw >>> 24) & 0x00ff00ff | (laneLsw << 24 | laneLsw >>> 8) & 0xff00ff00;

            // Squeeze state to retrieve hash
            hashWords.push(laneLsw);
            hashWords.push(laneMsw);
          }

          // Return final computed hash
          return new WordArray(hashWords, outputLengthBytes);
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._state = this._state.slice(0);
          var state = clone._state;
          for (var _i5 = 0; _i5 < 25; _i5 += 1) {
            state[_i5] = state[_i5].clone();
          }
          return clone;
        };
        return SHA3Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA3('message');
       *     var hash = CryptoJS.SHA3(wordArray);
       */
      var SHA3 = exports('SHA3', Hasher._createHelper(SHA3Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA3(message, key);
       */
      var HmacSHA3 = exports('HmacSHA3', Hasher._createHmacHelper(SHA3Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sha384.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './x64-core.js', './sha512.js'], function (exports) {
  var _inheritsLoose, cclegacy, X64WordArray, X64Word, SHA512Algo;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      X64WordArray = module.X64WordArray;
      X64Word = module.X64Word;
    }, function (module) {
      SHA512Algo = module.SHA512Algo;
    }],
    execute: function () {
      cclegacy._RF.push({}, "26b09wjwwZHo5a8HTFT4gRG", "sha384", undefined);

      /**
       * SHA-384 hash algorithm.
       */
      var SHA384Algo = exports('SHA384Algo', /*#__PURE__*/function (_SHA512Algo) {
        _inheritsLoose(SHA384Algo, _SHA512Algo);
        function SHA384Algo() {
          return _SHA512Algo.apply(this, arguments) || this;
        }
        var _proto = SHA384Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new X64WordArray([new X64Word(0xcbbb9d5d, 0xc1059ed8), new X64Word(0x629a292a, 0x367cd507), new X64Word(0x9159015a, 0x3070dd17), new X64Word(0x152fecd8, 0xf70e5939), new X64Word(0x67332667, 0xffc00b31), new X64Word(0x8eb44a87, 0x68581511), new X64Word(0xdb0c2e0d, 0x64f98fa7), new X64Word(0x47b5481d, 0xbefa4fa4)]);
        };
        _proto._doFinalize = function _doFinalize() {
          var hash = _SHA512Algo.prototype._doFinalize.call(this);
          hash.sigBytes -= 16;
          return hash;
        };
        return SHA384Algo;
      }(SHA512Algo));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA384('message');
       *     var hash = CryptoJS.SHA384(wordArray);
       */
      var SHA384 = exports('SHA384', SHA512Algo._createHelper(SHA384Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA384(message, key);
       */
      var HmacSHA384 = exports('HmacSHA384', SHA512Algo._createHmacHelper(SHA384Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sha512.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js', './x64-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, Hasher, X64Word, X64WordArray;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      Hasher = module.Hasher;
    }, function (module) {
      X64Word = module.X64Word;
      X64WordArray = module.X64WordArray;
    }],
    execute: function () {
      cclegacy._RF.push({}, "1af0ffWQF9CeZJi/mIeTtB7", "sha512", undefined);

      // Constants
      var K = [new X64Word(0x428a2f98, 0xd728ae22), new X64Word(0x71374491, 0x23ef65cd), new X64Word(0xb5c0fbcf, 0xec4d3b2f), new X64Word(0xe9b5dba5, 0x8189dbbc), new X64Word(0x3956c25b, 0xf348b538), new X64Word(0x59f111f1, 0xb605d019), new X64Word(0x923f82a4, 0xaf194f9b), new X64Word(0xab1c5ed5, 0xda6d8118), new X64Word(0xd807aa98, 0xa3030242), new X64Word(0x12835b01, 0x45706fbe), new X64Word(0x243185be, 0x4ee4b28c), new X64Word(0x550c7dc3, 0xd5ffb4e2), new X64Word(0x72be5d74, 0xf27b896f), new X64Word(0x80deb1fe, 0x3b1696b1), new X64Word(0x9bdc06a7, 0x25c71235), new X64Word(0xc19bf174, 0xcf692694), new X64Word(0xe49b69c1, 0x9ef14ad2), new X64Word(0xefbe4786, 0x384f25e3), new X64Word(0x0fc19dc6, 0x8b8cd5b5), new X64Word(0x240ca1cc, 0x77ac9c65), new X64Word(0x2de92c6f, 0x592b0275), new X64Word(0x4a7484aa, 0x6ea6e483), new X64Word(0x5cb0a9dc, 0xbd41fbd4), new X64Word(0x76f988da, 0x831153b5), new X64Word(0x983e5152, 0xee66dfab), new X64Word(0xa831c66d, 0x2db43210), new X64Word(0xb00327c8, 0x98fb213f), new X64Word(0xbf597fc7, 0xbeef0ee4), new X64Word(0xc6e00bf3, 0x3da88fc2), new X64Word(0xd5a79147, 0x930aa725), new X64Word(0x06ca6351, 0xe003826f), new X64Word(0x14292967, 0x0a0e6e70), new X64Word(0x27b70a85, 0x46d22ffc), new X64Word(0x2e1b2138, 0x5c26c926), new X64Word(0x4d2c6dfc, 0x5ac42aed), new X64Word(0x53380d13, 0x9d95b3df), new X64Word(0x650a7354, 0x8baf63de), new X64Word(0x766a0abb, 0x3c77b2a8), new X64Word(0x81c2c92e, 0x47edaee6), new X64Word(0x92722c85, 0x1482353b), new X64Word(0xa2bfe8a1, 0x4cf10364), new X64Word(0xa81a664b, 0xbc423001), new X64Word(0xc24b8b70, 0xd0f89791), new X64Word(0xc76c51a3, 0x0654be30), new X64Word(0xd192e819, 0xd6ef5218), new X64Word(0xd6990624, 0x5565a910), new X64Word(0xf40e3585, 0x5771202a), new X64Word(0x106aa070, 0x32bbd1b8), new X64Word(0x19a4c116, 0xb8d2d0c8), new X64Word(0x1e376c08, 0x5141ab53), new X64Word(0x2748774c, 0xdf8eeb99), new X64Word(0x34b0bcb5, 0xe19b48a8), new X64Word(0x391c0cb3, 0xc5c95a63), new X64Word(0x4ed8aa4a, 0xe3418acb), new X64Word(0x5b9cca4f, 0x7763e373), new X64Word(0x682e6ff3, 0xd6b2b8a3), new X64Word(0x748f82ee, 0x5defb2fc), new X64Word(0x78a5636f, 0x43172f60), new X64Word(0x84c87814, 0xa1f0ab72), new X64Word(0x8cc70208, 0x1a6439ec), new X64Word(0x90befffa, 0x23631e28), new X64Word(0xa4506ceb, 0xde82bde9), new X64Word(0xbef9a3f7, 0xb2c67915), new X64Word(0xc67178f2, 0xe372532b), new X64Word(0xca273ece, 0xea26619c), new X64Word(0xd186b8c7, 0x21c0c207), new X64Word(0xeada7dd6, 0xcde0eb1e), new X64Word(0xf57d4f7f, 0xee6ed178), new X64Word(0x06f067aa, 0x72176fba), new X64Word(0x0a637dc5, 0xa2c898a6), new X64Word(0x113f9804, 0xbef90dae), new X64Word(0x1b710b35, 0x131c471b), new X64Word(0x28db77f5, 0x23047d84), new X64Word(0x32caab7b, 0x40c72493), new X64Word(0x3c9ebe0a, 0x15c9bebc), new X64Word(0x431d67c4, 0x9c100d4c), new X64Word(0x4cc5d4be, 0xcb3e42b6), new X64Word(0x597f299c, 0xfc657e2a), new X64Word(0x5fcb6fab, 0x3ad6faec), new X64Word(0x6c44198c, 0x4a475817)];

      // Reusable objects
      var W = [];
      for (var i = 0; i < 80; i += 1) {
        W[i] = new X64Word();
      }

      /**
       * SHA-512 hash algorithm.
       */
      var SHA512Algo = exports('SHA512Algo', /*#__PURE__*/function (_Hasher) {
        _inheritsLoose(SHA512Algo, _Hasher);
        function SHA512Algo() {
          var _this;
          _this = _Hasher.call(this) || this;
          _this.blockSize = 1024 / 32;
          return _this;
        }
        var _proto = SHA512Algo.prototype;
        _proto._doReset = function _doReset() {
          this._hash = new X64WordArray([new X64Word(0x6a09e667, 0xf3bcc908), new X64Word(0xbb67ae85, 0x84caa73b), new X64Word(0x3c6ef372, 0xfe94f82b), new X64Word(0xa54ff53a, 0x5f1d36f1), new X64Word(0x510e527f, 0xade682d1), new X64Word(0x9b05688c, 0x2b3e6c1f), new X64Word(0x1f83d9ab, 0xfb41bd6b), new X64Word(0x5be0cd19, 0x137e2179)]);
        };
        _proto._doProcessBlock = function _doProcessBlock(M, offset) {
          // Shortcuts
          var H = this._hash.words;
          var H0 = H[0];
          var H1 = H[1];
          var H2 = H[2];
          var H3 = H[3];
          var H4 = H[4];
          var H5 = H[5];
          var H6 = H[6];
          var H7 = H[7];
          var H0h = H0.high;
          var H0l = H0.low;
          var H1h = H1.high;
          var H1l = H1.low;
          var H2h = H2.high;
          var H2l = H2.low;
          var H3h = H3.high;
          var H3l = H3.low;
          var H4h = H4.high;
          var H4l = H4.low;
          var H5h = H5.high;
          var H5l = H5.low;
          var H6h = H6.high;
          var H6l = H6.low;
          var H7h = H7.high;
          var H7l = H7.low;

          // Working variables
          var ah = H0h;
          var al = H0l;
          var bh = H1h;
          var bl = H1l;
          var ch = H2h;
          var cl = H2l;
          var dh = H3h;
          var dl = H3l;
          var eh = H4h;
          var el = H4l;
          var fh = H5h;
          var fl = H5l;
          var gh = H6h;
          var gl = H6l;
          var hh = H7h;
          var hl = H7l;

          // Rounds
          for (var _i = 0; _i < 80; _i += 1) {
            var Wil = void 0;
            var Wih = void 0;

            // Shortcut
            var Wi = W[_i];

            // Extend message
            if (_i < 16) {
              Wi.high = M[offset + _i * 2] | 0;
              Wih = Wi.high;
              Wi.low = M[offset + _i * 2 + 1] | 0;
              Wil = Wi.low;
            } else {
              // Gamma0
              var gamma0x = W[_i - 15];
              var gamma0xh = gamma0x.high;
              var gamma0xl = gamma0x.low;
              var gamma0h = (gamma0xh >>> 1 | gamma0xl << 31) ^ (gamma0xh >>> 8 | gamma0xl << 24) ^ gamma0xh >>> 7;
              var gamma0l = (gamma0xl >>> 1 | gamma0xh << 31) ^ (gamma0xl >>> 8 | gamma0xh << 24) ^ (gamma0xl >>> 7 | gamma0xh << 25);

              // Gamma1
              var gamma1x = W[_i - 2];
              var gamma1xh = gamma1x.high;
              var gamma1xl = gamma1x.low;
              var gamma1h = (gamma1xh >>> 19 | gamma1xl << 13) ^ (gamma1xh << 3 | gamma1xl >>> 29) ^ gamma1xh >>> 6;
              var gamma1l = (gamma1xl >>> 19 | gamma1xh << 13) ^ (gamma1xl << 3 | gamma1xh >>> 29) ^ (gamma1xl >>> 6 | gamma1xh << 26);

              // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
              var Wi7 = W[_i - 7];
              var Wi7h = Wi7.high;
              var Wi7l = Wi7.low;
              var Wi16 = W[_i - 16];
              var Wi16h = Wi16.high;
              var Wi16l = Wi16.low;
              Wil = gamma0l + Wi7l;
              Wih = gamma0h + Wi7h + (Wil >>> 0 < gamma0l >>> 0 ? 1 : 0);
              Wil += gamma1l;
              Wih = Wih + gamma1h + (Wil >>> 0 < gamma1l >>> 0 ? 1 : 0);
              Wil += Wi16l;
              Wih = Wih + Wi16h + (Wil >>> 0 < Wi16l >>> 0 ? 1 : 0);
              Wi.high = Wih;
              Wi.low = Wil;
            }
            var chh = eh & fh ^ ~eh & gh;
            var chl = el & fl ^ ~el & gl;
            var majh = ah & bh ^ ah & ch ^ bh & ch;
            var majl = al & bl ^ al & cl ^ bl & cl;
            var sigma0h = (ah >>> 28 | al << 4) ^ (ah << 30 | al >>> 2) ^ (ah << 25 | al >>> 7);
            var sigma0l = (al >>> 28 | ah << 4) ^ (al << 30 | ah >>> 2) ^ (al << 25 | ah >>> 7);
            var sigma1h = (eh >>> 14 | el << 18) ^ (eh >>> 18 | el << 14) ^ (eh << 23 | el >>> 9);
            var sigma1l = (el >>> 14 | eh << 18) ^ (el >>> 18 | eh << 14) ^ (el << 23 | eh >>> 9);

            // t1 = h + sigma1 + ch + K[i] + W[i]
            var Ki = K[_i];
            var Kih = Ki.high;
            var Kil = Ki.low;
            var t1l = hl + sigma1l;
            var t1h = hh + sigma1h + (t1l >>> 0 < hl >>> 0 ? 1 : 0);
            t1l += chl;
            t1h = t1h + chh + (t1l >>> 0 < chl >>> 0 ? 1 : 0);
            t1l += Kil;
            t1h = t1h + Kih + (t1l >>> 0 < Kil >>> 0 ? 1 : 0);
            t1l += Wil;
            t1h = t1h + Wih + (t1l >>> 0 < Wil >>> 0 ? 1 : 0);

            // t2 = sigma0 + maj
            var t2l = sigma0l + majl;
            var t2h = sigma0h + majh + (t2l >>> 0 < sigma0l >>> 0 ? 1 : 0);

            // Update working variables
            hh = gh;
            hl = gl;
            gh = fh;
            gl = fl;
            fh = eh;
            fl = el;
            el = dl + t1l | 0;
            eh = dh + t1h + (el >>> 0 < dl >>> 0 ? 1 : 0) | 0;
            dh = ch;
            dl = cl;
            ch = bh;
            cl = bl;
            bh = ah;
            bl = al;
            al = t1l + t2l | 0;
            ah = t1h + t2h + (al >>> 0 < t1l >>> 0 ? 1 : 0) | 0;
          }

          // Intermediate hash value
          H0.low = H0l + al;
          H0l = H0.low;
          H0.high = H0h + ah + (H0l >>> 0 < al >>> 0 ? 1 : 0);
          H1.low = H1l + bl;
          H1l = H1.low;
          H1.high = H1h + bh + (H1l >>> 0 < bl >>> 0 ? 1 : 0);
          H2.low = H2l + cl;
          H2l = H2.low;
          H2.high = H2h + ch + (H2l >>> 0 < cl >>> 0 ? 1 : 0);
          H3.low = H3l + dl;
          H3l = H3.low;
          H3.high = H3h + dh + (H3l >>> 0 < dl >>> 0 ? 1 : 0);
          H4.low = H4l + el;
          H4l = H4.low;
          H4.high = H4h + eh + (H4l >>> 0 < el >>> 0 ? 1 : 0);
          H5.low = H5l + fl;
          H5l = H5.low;
          H5.high = H5h + fh + (H5l >>> 0 < fl >>> 0 ? 1 : 0);
          H6.low = H6l + gl;
          H6l = H6.low;
          H6.high = H6h + gh + (H6l >>> 0 < gl >>> 0 ? 1 : 0);
          H7.low = H7l + hl;
          H7l = H7.low;
          H7.high = H7h + hh + (H7l >>> 0 < hl >>> 0 ? 1 : 0);
        };
        _proto._doFinalize = function _doFinalize() {
          // Shortcuts
          var data = this._data;
          var dataWords = data.words;
          var nBitsTotal = this._nDataBytes * 8;
          var nBitsLeft = data.sigBytes * 8;

          // Add padding
          dataWords[nBitsLeft >>> 5] |= 0x80 << 24 - nBitsLeft % 32;
          dataWords[(nBitsLeft + 128 >>> 10 << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
          dataWords[(nBitsLeft + 128 >>> 10 << 5) + 31] = nBitsTotal;
          data.sigBytes = dataWords.length * 4;

          // Hash final blocks
          this._process();

          // Convert hash to 32-bit word array before returning
          var hash = this._hash.toX32();

          // Return final computed hash
          return hash;
        };
        _proto.clone = function clone() {
          var clone = _Hasher.prototype.clone.call(this);
          clone._hash = this._hash.clone();
          return clone;
        };
        return SHA512Algo;
      }(Hasher));

      /**
       * Shortcut function to the hasher's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       *
       * @return {WordArray} The hash.
       *
       * @static
       *
       * @example
       *
       *     var hash = CryptoJS.SHA512('message');
       *     var hash = CryptoJS.SHA512(wordArray);
       */
      var SHA512 = exports('SHA512', Hasher._createHelper(SHA512Algo));

      /**
       * Shortcut function to the HMAC's object interface.
       *
       * @param {WordArray|string} message The message to hash.
       * @param {WordArray|string} key The secret key.
       *
       * @return {WordArray} The HMAC.
       *
       * @static
       *
       * @example
       *
       *     var hmac = CryptoJS.HmacSHA512(message, key);
       */
      var HmacSHA512 = exports('HmacSHA512', Hasher._createHmacHelper(SHA512Algo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/SheetData.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "6f4b3BqRvxB5IQ5JbyZaYM/", "SheetData", undefined);
      var SheetData = exports('default', /*#__PURE__*/function () {
        function SheetData() {
          this.level = [];
          this.ball = [];
          this.speed = [];
          this.bullet = [];
        }
        var _proto = SheetData.prototype;
        _proto.setData = function setData(data) {
          this.level = data[0];
          this.ball = data[1];
          this.speed = data[2];
          this.bullet = data[3];
        };
        _proto.setDefault = function setDefault() {
          for (var i = 1; i < 11; i++) {
            this.level[i] = i;
            this.ball[i] = Math.floor(i / 2) + 4;
            this.speed[i] = (3 + i) / 7.2;
            this.bullet[i] = i + 7;
          }
        };
        return SheetData;
      }());
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sign.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './sign3.ts'], function (exports) {
  var _asyncToGenerator, _regeneratorRuntime, cclegacy, FlattenedSign;
  return {
    setters: [function (module) {
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      FlattenedSign = module.FlattenedSign;
    }],
    execute: function () {
      cclegacy._RF.push({}, "1695bqiINxB6Ly0myqIxpVa", "sign", undefined);
      /**
       * The CompactSign class is used to build and sign Compact JWS strings.
       *
       * @example
       *
       * ```js
       * const jws = await new jose.CompactSign(
       *   new TextEncoder().encode('It’s a dangerous business, Frodo, going out your door.'),
       * )
       *   .setProtectedHeader({ alg: 'ES256' })
       *   .sign(privateKey)
       *
       * console.log(jws)
       * ```
       */
      var CompactSign = exports('CompactSign', /*#__PURE__*/function () {
        /** @param payload Binary representation of the payload to sign. */
        function CompactSign(payload) {
          this._flattened = void 0;
          this._flattened = new FlattenedSign(payload);
        }

        /**
         * Sets the JWS Protected Header on the Sign object.
         *
         * @param protectedHeader JWS Protected Header.
         */
        var _proto = CompactSign.prototype;
        _proto.setProtectedHeader = function setProtectedHeader(protectedHeader) {
          this._flattened.setProtectedHeader(protectedHeader);
          return this;
        }

        /**
         * Signs and resolves the value of the Compact JWS string.
         *
         * @param key Private Key or Secret to sign the JWS with. See
         *   {@link https://github.com/panva/jose/issues/210#jws-alg Algorithm Key Requirements}.
         * @param options JWS Sign options.
         */;
        _proto.sign = /*#__PURE__*/
        function () {
          var _sign = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(key, options) {
            var jws;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  _context.next = 2;
                  return this._flattened.sign(key, options);
                case 2:
                  jws = _context.sent;
                  if (!(jws.payload === undefined)) {
                    _context.next = 5;
                    break;
                  }
                  throw new TypeError('use the flattened module for creating JWS with b64: false');
                case 5:
                  return _context.abrupt("return", jws["protected"] + "." + jws.payload + "." + jws.signature);
                case 6:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function sign(_x, _x2) {
            return _sign.apply(this, arguments);
          }
          return sign;
        }();
        return CompactSign;
      }());
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sign2.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './sign.ts', './errors.ts', './buffer_utils.ts', './produce.ts'], function (exports) {
  var _inheritsLoose, _asyncToGenerator, _regeneratorRuntime, cclegacy, CompactSign, JWTInvalid, encoder, ProduceJWT;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      CompactSign = module.CompactSign;
    }, function (module) {
      JWTInvalid = module.JWTInvalid;
    }, function (module) {
      encoder = module.encoder;
    }, function (module) {
      ProduceJWT = module.ProduceJWT;
    }],
    execute: function () {
      cclegacy._RF.push({}, "5995biwjLlO7qEUtKeDlYUx", "sign", undefined);

      /**
       * The SignJWT class is used to build and sign Compact JWS formatted JSON Web Tokens.
       *
       * @example
       *
       * Usage with a symmetric secret
       *
       * ```js
       * const secret = new TextEncoder().encode(
       *   'cc7e0d44fd473002f1c42167459001140ec6389b7353f8088f4d9a95f2f596f2',
       * )
       * const alg = 'HS256'
       *
       * const jwt = await new jose.SignJWT({ 'urn:example:claim': true })
       *   .setProtectedHeader({ alg })
       *   .setIssuedAt()
       *   .setIssuer('urn:example:issuer')
       *   .setAudience('urn:example:audience')
       *   .setExpirationTime('2h')
       *   .sign(secret)
       *
       * console.log(jwt)
       * ```
       *
       * @example
       *
       * Usage with a private PKCS#8 encoded RSA key
       *
       * ```js
       * const alg = 'RS256'
       * const pkcs8 = `-----BEGIN PRIVATE KEY-----
       * MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCFg4UrY5xtulv
       * /NXKmL1J4qI1SopAfTNMo3X7p+kJO7plqUYjzaztcre1qfh0m33Sm1Q8oPbO/GpP
       * MU1/HgcceytgJ/b4UwufVVMl9BrMDYG8moDBylbVupFQS3Ly1L9i/iFG9Z9A9xzY
       * Zzf799A45bnvNXL6s2glzvjiRvfQ2NDF0anTcnZLcYtC7ugq1IMM+ihAcPfw8Qw2
       * chN/SmP4qAM+PKaQwagmU7doqmmyN9u38AfoYZ1GCFhEs5TBBT6H6h9YdHeVtiIq
       * 1c+fl03biSIfLrV7dUBD39gBmXBcL/30Ya3D82mCEUC4zg/UkOfQOmkmV3Lc8YUL
       * QZ8EJkBLAgMBAAECggEAVuVE/KEP6323WjpbBdAIv7HGahGrgGANvbxZsIhm34ls
       * VOPK0XDegZkhAybMZHjRhp+gwVxX5ChC+J3cUpOBH5FNxElgW6HizD2Jcq6t6LoL
       * YgPSrfEHm71iHg8JsgrqfUnGYFzMJmv88C6WdCtpgG/qJV1K00/Ly1G1QKoBffEs
       * +v4fAMJrCbUdCz1qWto+PU+HLMEo+krfEpGgcmtZeRlDADh8cETMQlgQfQX2VWq/
       * aAP4a1SXmo+j0cvRU4W5Fj0RVwNesIpetX2ZFz4p/JmB5sWFEj/fC7h5z2lq+6Bm
       * e2T3BHtXkIxoBW0/pYVnASC8P2puO5FnVxDmWuHDYQKBgQDTuuBd3+0tSFVEX+DU
       * 5qpFmHm5nyGItZRJTS+71yg5pBxq1KqNCUjAtbxR0q//fwauakh+BwRVCPOrqsUG
       * jBSb3NYE70Srp6elqxgkE54PwQx4Mr6exJPnseM9U4K+hULllf5yjM9edreJE1nV
       * NVgFjeyafQhrHKwgr7PERJ/ikwKBgQDqqsT1M+EJLmI1HtCspOG6cu7q3gf/wKRh
       * E8tu84i3YyBnI8uJkKy92RNVI5fvpBARe3tjSdM25rr2rcrcmF/5g6Q9ImxZPGCt
       * 86eOgO9ErNtbc4TEgybsP319UE4O41aKeNiBTAZKoYCxv/dMqG0j4avmWzd+foHq
       * gSNUvR2maQKBgQCYeqOsV2B6VPY7KIVFLd0AA9/dwvEmgAYLiA/RShDI+hwQ/5jX
       * uxDu37KAhqeC65sHLrmIMUt4Zdr+DRyZK3aIDNEAesPMjw/X6lCXYp1ZISD2yyym
       * MFGH8X8CIkstI9Faf9vf6PJKSFrC1/HA7wq17VCwrUzLvrljTMW8meM/CwKBgCpo
       * 2leGHLFQFKeM/iF1WuYbR1pi7gcmhY6VyTowARFDdOOu8GXYI5/bz0afvCGvAMho
       * DJCREv7lC/zww6zCTPYG+HOj+PjXlJFba3ixjIxYwPvyEJiDK1Ge18sB7Fl8dHNq
       * C5ayaqCqN1voWYUdGzxU2IA1E/5kVo5O8FesJeOhAoGBAImJbZFf+D5kA32Xxhac
       * 59lLWBCsocvvbd1cvDMNlRywAAyhsCb1SuX4nEAK9mrSBdfmoF2Nm3eilfsOds0f
       * K5mX069IKG82CMqh3Mzptd7e7lyb9lsoGO0BAtjho3cWtha/UZ70vfaMzGuZ6JmQ
       * ak6k+8+UFd93M4z0Qo74OhXB
       * -----END PRIVATE KEY-----`
       * const privateKey = await jose.importPKCS8(pkcs8, alg)
       *
       * const jwt = await new jose.SignJWT({ 'urn:example:claim': true })
       *   .setProtectedHeader({ alg })
       *   .setIssuedAt()
       *   .setIssuer('urn:example:issuer')
       *   .setAudience('urn:example:audience')
       *   .setExpirationTime('2h')
       *   .sign(privateKey)
       *
       * console.log(jwt)
       * ```
       *
       * @example
       *
       * Usage with a private JWK encoded RSA key
       *
       * ```js
       * const alg = 'RS256'
       * const jwk = {
       *   kty: 'RSA',
       *   n: 'whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw',
       *   e: 'AQAB',
       *   d: 'VuVE_KEP6323WjpbBdAIv7HGahGrgGANvbxZsIhm34lsVOPK0XDegZkhAybMZHjRhp-gwVxX5ChC-J3cUpOBH5FNxElgW6HizD2Jcq6t6LoLYgPSrfEHm71iHg8JsgrqfUnGYFzMJmv88C6WdCtpgG_qJV1K00_Ly1G1QKoBffEs-v4fAMJrCbUdCz1qWto-PU-HLMEo-krfEpGgcmtZeRlDADh8cETMQlgQfQX2VWq_aAP4a1SXmo-j0cvRU4W5Fj0RVwNesIpetX2ZFz4p_JmB5sWFEj_fC7h5z2lq-6Bme2T3BHtXkIxoBW0_pYVnASC8P2puO5FnVxDmWuHDYQ',
       *   p: '07rgXd_tLUhVRF_g1OaqRZh5uZ8hiLWUSU0vu9coOaQcatSqjQlIwLW8UdKv_38GrmpIfgcEVQjzq6rFBowUm9zWBO9Eq6enpasYJBOeD8EMeDK-nsST57HjPVOCvoVC5ZX-cozPXna3iRNZ1TVYBY3smn0IaxysIK-zxESf4pM',
       *   q: '6qrE9TPhCS5iNR7QrKThunLu6t4H_8CkYRPLbvOIt2MgZyPLiZCsvdkTVSOX76QQEXt7Y0nTNua69q3K3Jhf-YOkPSJsWTxgrfOnjoDvRKzbW3OExIMm7D99fVBODuNWinjYgUwGSqGAsb_3TKhtI-Gr5ls3fn6B6oEjVL0dpmk',
       *   dp: 'mHqjrFdgelT2OyiFRS3dAAPf3cLxJoAGC4gP0UoQyPocEP-Y17sQ7t-ygIanguubBy65iDFLeGXa_g0cmSt2iAzRAHrDzI8P1-pQl2KdWSEg9ssspjBRh_F_AiJLLSPRWn_b3-jySkhawtfxwO8Kte1QsK1My765Y0zFvJnjPws',
       *   dq: 'KmjaV4YcsVAUp4z-IXVa5htHWmLuByaFjpXJOjABEUN0467wZdgjn9vPRp-8Ia8AyGgMkJES_uUL_PDDrMJM9gb4c6P4-NeUkVtreLGMjFjA-_IQmIMrUZ7XywHsWXx0c2oLlrJqoKo3W-hZhR0bPFTYgDUT_mRWjk7wV6wl46E',
       *   qi: 'iYltkV_4PmQDfZfGFpzn2UtYEKyhy-9t3Vy8Mw2VHLAADKGwJvVK5ficQAr2atIF1-agXY2bd6KV-w52zR8rmZfTr0gobzYIyqHczOm13t7uXJv2WygY7QEC2OGjdxa2Fr9RnvS99ozMa5nomZBqTqT7z5QV33czjPRCjvg6FcE',
       * }
       * const privateKey = await jose.importJWK(jwk, alg)
       *
       * const jwt = await new jose.SignJWT({ 'urn:example:claim': true })
       *   .setProtectedHeader({ alg })
       *   .setIssuedAt()
       *   .setIssuer('urn:example:issuer')
       *   .setAudience('urn:example:audience')
       *   .setExpirationTime('2h')
       *   .sign(privateKey)
       *
       * console.log(jwt)
       * ```
       */
      var SignJWT = exports('SignJWT', /*#__PURE__*/function (_ProduceJWT) {
        _inheritsLoose(SignJWT, _ProduceJWT);
        function SignJWT() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _ProduceJWT.call.apply(_ProduceJWT, [this].concat(args)) || this;
          _this._protectedHeader = void 0;
          return _this;
        }
        var _proto = SignJWT.prototype;
        /**
         * Sets the JWS Protected Header on the SignJWT object.
         *
         * @param protectedHeader JWS Protected Header. Must contain an "alg" (JWS Algorithm) property.
         */
        _proto.setProtectedHeader = function setProtectedHeader(protectedHeader) {
          this._protectedHeader = protectedHeader;
          return this;
        }

        /**
         * Signs and returns the JWT.
         *
         * @param key Private Key or Secret to sign the JWT with. See
         *   {@link https://github.com/panva/jose/issues/210#jws-alg Algorithm Key Requirements}.
         * @param options JWT Sign options.
         */;
        _proto.sign = /*#__PURE__*/
        function () {
          var _sign = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(key, options) {
            var _this$_protectedHeade;
            var sig;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)));
                  sig.setProtectedHeader(this._protectedHeader);
                  if (!(Array.isArray((_this$_protectedHeade = this._protectedHeader) == null ? void 0 : _this$_protectedHeade.crit) && this._protectedHeader.crit.includes('b64') &&
                  // @ts-expect-error
                  this._protectedHeader.b64 === false)) {
                    _context.next = 4;
                    break;
                  }
                  throw new JWTInvalid('JWTs MUST NOT use unencoded payload');
                case 4:
                  return _context.abrupt("return", sig.sign(key, options));
                case 5:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function sign(_x, _x2) {
            return _sign.apply(this, arguments);
          }
          return sign;
        }();
        return SignJWT;
      }(ProduceJWT));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sign3.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './base64url.ts', './sign4.ts', './buffer_utils.ts', './check_key_type.ts', './is_disjoint.ts', './validate_crit.ts', './errors.ts'], function (exports) {
  var _asyncToGenerator, _regeneratorRuntime, _extends, cclegacy, encode, sign, decoder, encoder, concat, checkKeyType, isDisjoint, validateCrit, JWSInvalid;
  return {
    setters: [function (module) {
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
      _extends = module.extends;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      encode = module.encode;
    }, function (module) {
      sign = module.default;
    }, function (module) {
      decoder = module.decoder;
      encoder = module.encoder;
      concat = module.concat;
    }, function (module) {
      checkKeyType = module.default;
    }, function (module) {
      isDisjoint = module.default;
    }, function (module) {
      validateCrit = module.default;
    }, function (module) {
      JWSInvalid = module.JWSInvalid;
    }],
    execute: function () {
      cclegacy._RF.push({}, "92835BBBTpGSbKbsOjjk/hY", "sign", undefined);

      /**
       * The FlattenedSign class is used to build and sign Flattened JWS objects.
       *
       * @example
       *
       * ```js
       * const jws = await new jose.FlattenedSign(
       *   new TextEncoder().encode('It’s a dangerous business, Frodo, going out your door.'),
       * )
       *   .setProtectedHeader({ alg: 'ES256' })
       *   .sign(privateKey)
       *
       * console.log(jws)
       * ```
       */
      var FlattenedSign = exports('FlattenedSign', /*#__PURE__*/function () {
        /** @param payload Binary representation of the payload to sign. */
        function FlattenedSign(payload) {
          this._payload = void 0;
          this._protectedHeader = void 0;
          this._unprotectedHeader = void 0;
          if (!(payload instanceof Uint8Array)) {
            throw new TypeError('payload must be an instance of Uint8Array');
          }
          this._payload = payload;
        }

        /**
         * Sets the JWS Protected Header on the FlattenedSign object.
         *
         * @param protectedHeader JWS Protected Header.
         */
        var _proto = FlattenedSign.prototype;
        _proto.setProtectedHeader = function setProtectedHeader(protectedHeader) {
          if (this._protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
          }
          this._protectedHeader = protectedHeader;
          return this;
        }

        /**
         * Sets the JWS Unprotected Header on the FlattenedSign object.
         *
         * @param unprotectedHeader JWS Unprotected Header.
         */;
        _proto.setUnprotectedHeader = function setUnprotectedHeader(unprotectedHeader) {
          if (this._unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
          }
          this._unprotectedHeader = unprotectedHeader;
          return this;
        }

        /**
         * Signs and resolves the value of the Flattened JWS object.
         *
         * @param key Private Key or Secret to sign the JWS with. See
         *   {@link https://github.com/panva/jose/issues/210#jws-alg Algorithm Key Requirements}.
         * @param options JWS Sign options.
         */;
        _proto.sign = /*#__PURE__*/
        function () {
          var _sign2 = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(key, options) {
            var joseHeader, extensions, b64, alg, payload, protectedHeader, data, signature, jws;
            return _regeneratorRuntime().wrap(function _callee$(_context) {
              while (1) switch (_context.prev = _context.next) {
                case 0:
                  if (!(!this._protectedHeader && !this._unprotectedHeader)) {
                    _context.next = 2;
                    break;
                  }
                  throw new JWSInvalid('either setProtectedHeader or setUnprotectedHeader must be called before #sign()');
                case 2:
                  if (isDisjoint(this._protectedHeader, this._unprotectedHeader)) {
                    _context.next = 4;
                    break;
                  }
                  throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
                case 4:
                  joseHeader = _extends({}, this._protectedHeader, this._unprotectedHeader);
                  extensions = validateCrit(JWSInvalid, new Map([['b64', true]]), options == null ? void 0 : options.crit, this._protectedHeader, joseHeader);
                  b64 = true;
                  if (!extensions.has('b64')) {
                    _context.next = 11;
                    break;
                  }
                  b64 = this._protectedHeader.b64;
                  if (!(typeof b64 !== 'boolean')) {
                    _context.next = 11;
                    break;
                  }
                  throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
                case 11:
                  alg = joseHeader.alg;
                  if (!(typeof alg !== 'string' || !alg)) {
                    _context.next = 14;
                    break;
                  }
                  throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
                case 14:
                  checkKeyType(alg, key, 'sign');
                  payload = this._payload;
                  if (b64) {
                    payload = encoder.encode(encode(payload));
                  }
                  if (this._protectedHeader) {
                    protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
                  } else {
                    protectedHeader = encoder.encode('');
                  }
                  data = concat(protectedHeader, encoder.encode('.'), payload);
                  _context.next = 21;
                  return sign(alg, key, data);
                case 21:
                  signature = _context.sent;
                  jws = {
                    signature: encode(signature),
                    payload: ''
                  };
                  if (b64) {
                    jws.payload = decoder.decode(payload);
                  }
                  if (this._unprotectedHeader) {
                    jws.header = this._unprotectedHeader;
                  }
                  if (this._protectedHeader) {
                    jws["protected"] = decoder.decode(protectedHeader);
                  }
                  return _context.abrupt("return", jws);
                case 27:
                case "end":
                  return _context.stop();
              }
            }, _callee, this);
          }));
          function sign$1(_x, _x2) {
            return _sign2.apply(this, arguments);
          }
          return sign$1;
        }();
        return FlattenedSign;
      }());
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/sign4.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './check_key_length.ts', './get_sign_verify_key.ts', './subtle_dsa.ts'], function (exports) {
  var _asyncToGenerator, _regeneratorRuntime, cclegacy, checkKeyLength, getCryptoKey, subtleDsa;
  return {
    setters: [function (module) {
      _asyncToGenerator = module.asyncToGenerator;
      _regeneratorRuntime = module.regeneratorRuntime;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      checkKeyLength = module.default;
    }, function (module) {
      getCryptoKey = module.default;
    }, function (module) {
      subtleDsa = module.default;
    }],
    execute: function () {
      cclegacy._RF.push({}, "ccab04lx+BGtIvtvczBhWkL", "sign", undefined);
      // import crypto from './webcrypto'

      var sign = exports('default', /*#__PURE__*/function () {
        var _ref = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(alg, key, data) {
          var cryptoKey, signature;
          return _regeneratorRuntime().wrap(function _callee$(_context) {
            while (1) switch (_context.prev = _context.next) {
              case 0:
                _context.next = 2;
                return getCryptoKey(alg, key, 'sign');
              case 2:
                cryptoKey = _context.sent;
                checkKeyLength(alg, cryptoKey);
                _context.next = 6;
                return crypto.subtle.sign(subtleDsa(alg, cryptoKey.algorithm), cryptoKey, data);
              case 6:
                signature = _context.sent;
                return _context.abrupt("return", new Uint8Array(signature));
              case 8:
              case "end":
                return _context.stop();
            }
          }, _callee);
        }));
        return function sign(_x, _x2, _x3) {
          return _ref.apply(this, arguments);
        };
      }());
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/SingletonManger.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _createForOfIteratorHelperLoose, _createClass, cclegacy, js;
  return {
    setters: [function (module) {
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      js = module.js;
    }],
    execute: function () {
      cclegacy._RF.push({}, "4b243ts6O5Le5pOCKcWe6yx", "SingletonManger", undefined);
      /**
       * @Author 蕭立品
       * @Description 模板資源管理器
       * @Date 2021-12-17 下午 06:42
       * @Version 1.0
       */
      var SingletManager = exports('default', /*#__PURE__*/function () {
        function SingletManager() {
          /**
           * 當前保存的所有單例物件
           * @type {Map<string, any>}
           * @private
           */
          this.componentClass = void 0;
          this.componentClass = new Map();
        }

        /**
         *  添加單例
         * @param {any} self - 要加入單例的class
         */
        var _proto = SingletManager.prototype;
        _proto.set = function set(self) {
          // console.log(self.constructor.name);
          // console.log(js.getClassName(self));

          var name = js.getClassName(self);
          if (!this.componentClass) this.componentClass = new Map();
          // console.error(this.componentClass);

          if (this.componentClass.has(name)) ;else {
            this.componentClass.set(name, self);
          }
        }

        /**
         * 拿取單例
         * @param {string} name - 名稱
         * @return {IBaseSingleton}
         */;
        _proto.get = function get(name) {
          if (!this.componentClass.has(name)) {
            // console.error("Adam", "當前物件尚未添加進管理器中", name);
            return null;
          }
          return this.componentClass.get(name);
        }

        /**
         * 獲取全部綁定單例的單例CLASS
         * @return {Map<string, any>}
         */;
        _proto.getAll = function getAll() {
          return this.componentClass;
        }

        /**
         * 清除所有
         */;
        _proto.deleteAll = function deleteAll() {
          for (var _iterator = _createForOfIteratorHelperLoose(this.componentClass.values()), _step; !(_step = _iterator()).done;) {
            var singleton = _step.value;
            singleton.clear();
          }
          this.componentClass = null;
        }

        /**
         * 清除單一
         * @param name
         */;
        _proto["delete"] = function _delete(name) {
          try {
            if (this.componentClass.has(name)) {
              this.componentClass.get(name).clear();
              this.componentClass["delete"](name);
            } else {
              // console.warn("查找不到該物件,無須清除");
            }
          } catch (error) {
            console.warn("查找不到該物件,無須清除");
          }
        };
        _createClass(SingletManager, null, [{
          key: "instance",
          get: function get() {
            if (!this._instance) {
              this._instance = new SingletManager();
            }
            return this._instance;
          }
        }]);
        return SingletManager;
      }());
      SingletManager._instance = void 0;
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/SpriteButton.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, cclegacy, _decorator, SpriteFrame, Sprite, Button;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      SpriteFrame = module.SpriteFrame;
      Sprite = module.Sprite;
      Button = module.Button;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "4999dP3T4RErpIUvsAif1Uj", "SpriteButton", undefined);
      var ccclass = _decorator.ccclass,
        property = _decorator.property;
      var SpriteButton = exports('default', (_dec = ccclass('SpriteButton'), _dec2 = property({
        type: SpriteFrame,
        tooltip: "預設Normal圖片"
      }), _dec3 = property({
        type: SpriteFrame,
        tooltip: "預設選擇按鈕圖片"
      }), _dec(_class = (_class2 = /*#__PURE__*/function (_Button) {
        _inheritsLoose(SpriteButton, _Button);
        function SpriteButton() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Button.call.apply(_Button, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "defaultNormalSprite", _descriptor, _assertThisInitialized(_this));
          // @property({ type: SpriteFrame, tooltip: "預設disabled般按鈕圖片" })
          // defaultDisabledSprite: SpriteFrame;
          _initializerDefineProperty(_this, "defaultSelectSprite", _descriptor2, _assertThisInitialized(_this));
          _this.needDisable = false;
          //這邊找時間寫成get set 方式轉換看會不會影響到toech end流程
          _this.isSelect = false;
          _this.sprite = void 0;
          return _this;
        }
        var _proto = SpriteButton.prototype;
        _proto.onLoad = function onLoad() {
          this.sprite = this.getComponent(Sprite);
        };
        _proto._onTouchEnded = function _onTouchEnded(event) {
          _Button.prototype._onTouchEnded.call(this, event);
          this.updateSpriteStatus();
        };
        _proto.initStatus = function initStatus(_needDisable, _isDisable) {
          if (_isDisable === void 0) {
            _isDisable = false;
          }
          this.needDisable = _needDisable;
          this.isSelect = _isDisable;
        };
        _proto.updateSpriteStatus = function updateSpriteStatus() {
          if (!this.needDisable) return;
          // console.log((this.interactable));
          var changeSprite = this.interactable ? this.defaultNormalSprite : this.disabledSprite;
          try {
            this.sprite.spriteFrame = this.isSelect ? this.defaultSelectSprite : changeSprite;
          } catch (error) {
            this.sprite = new Sprite();
            this.sprite.spriteFrame = this.isSelect ? this.defaultSelectSprite : changeSprite;
          }
        };
        return SpriteButton;
      }(Button), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "defaultNormalSprite", [_dec2], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "defaultSelectSprite", [_dec3], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: null
      })), _class2)) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/StatePatten.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './BaseSingleton.ts'], function (exports) {
  var _inheritsLoose, cclegacy, BaseSingleton;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      BaseSingleton = module.default;
    }],
    execute: function () {
      cclegacy._RF.push({}, "730dfrPU5hLIrsfizb+c/jC", "StatePatten", undefined);
      var State = exports('State', /*#__PURE__*/function () {
        function State() {
          this.context = void 0;
        }
        var _proto = State.prototype;
        _proto.setContext = function setContext(context) {
          this.context = context;
        };
        _proto.stayState = function stayState(data) {
          this.changeState(data);
        };
        return State;
      }());
      var Context = /*#__PURE__*/function (_BaseSingleton) {
        _inheritsLoose(Context, _BaseSingleton);
        function Context() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _BaseSingleton.call.apply(_BaseSingleton, [this].concat(args)) || this;
          /**
           * @type {State} A reference to the current state of the Context.
           */
          _this.state = void 0;
          _this.data = void 0;
          return _this;
        }
        var _proto2 = Context.prototype;
        // public isStateing: boolean;
        _proto2.clearState = function clearState() {
          this.state = null;
          this.data = null;
        };
        _proto2.checkState = function checkState() {
          return this.state == undefined ? false : true;
        }
        /**
         * The Context allows changing the State object at runtime.
        */;
        _proto2.transitionTo = function transitionTo(_class, data) {
          if (!(this.state instanceof _class)) {
            this.data = data ? data : null;
            var newT = new _class();
            this.state = newT;
            this.state.setContext(this);
            this.requestChange();
          } else {
            this.requestStay(data);
          }
        }

        /**
         * 舊方法
         */;
        _proto2.transitionTo_Old = function transitionTo_Old(state, data) {
          // if (this.state != null && MainModel.getClassName(<any>state) == MainModel.getClassName(this.state)) {
          //     console.log(`Context: NowState ${(this.state).constructor.name}.`);
          //     this.isStateing = true
          //     return
          // }
          // this.isStateing = false
          // console.log(`Context: Transition to ${(<any>state).constructor.name}.`);
          this.data = data ? data : null;
          this.state = state;
          // this.setMainScript()
          this.state.setContext(this);
          return this;
        }

        /**
         * The Context delegates part of its behavior to the current State object.
         */;
        _proto2.requestChange = function requestChange() {
          // console.log(`requestChange to ${js.getClassName(this.state)}`);
          this.state.changeState(this.data);
        };
        _proto2.requestStay = function requestStay(data) {
          this.data = data ? data : null;
          this.state.stayState(data);
        }
        //打包後變數會被混淆，導致無法知道誰是誰，因此就只能先這樣，等待可以找到被混淆後的js明子再說，暫時先放著了
        // public setMainScript() {
        //     /**想不到更好寫法 先暫時這樣定義單利，雖然多佔2x5個記憶體空間，但目前先這樣 */
        //     if (!(this.state as MainGameState).main && MainGame.instance) {
        //         (this.state as MainGameState).main = MainGame.instance
        //     }
        //     if (!(this.state as MainLobbyState).main && MainLobby.instance) {
        //         (this.state as MainLobbyState).main = MainLobby.instance
        //     }
        //     if (!(this.state as MainLoadingState).main && MainLoading.instance) {
        //         (this.state as MainLoadingState).main = MainLoading.instance
        //     }
        //     // console.log(`main:${(this.state as MainGameState).main}`);
        //     // console.log(`lobby:${(this.state as MainLobbyState).main}`);
        //     // console.log(`loading:${(this.state as MainLoadingState).main}`);
        // }
        ;

        return Context;
      }(BaseSingleton());
      var GameState = exports('GameState', /*#__PURE__*/function (_Context) {
        _inheritsLoose(GameState, _Context);
        function GameState() {
          return _Context.apply(this, arguments) || this;
        }
        return GameState;
      }(Context));
      var LobbyState = exports('LobbyState', /*#__PURE__*/function (_Context2) {
        _inheritsLoose(LobbyState, _Context2);
        function LobbyState() {
          return _Context2.apply(this, arguments) || this;
        }
        return LobbyState;
      }(Context));
      var PlayerState = exports('PlayerState', /*#__PURE__*/function (_Context3) {
        _inheritsLoose(PlayerState, _Context3);
        function PlayerState() {
          return _Context3.apply(this, arguments) || this;
        }
        return PlayerState;
      }(Context));
      var ViewState = exports('ViewState', /*#__PURE__*/function (_Context4) {
        _inheritsLoose(ViewState, _Context4);
        function ViewState() {
          return _Context4.apply(this, arguments) || this;
        }
        return ViewState;
      }(Context));
      var MessageState = exports('MessageState', /*#__PURE__*/function (_Context5) {
        _inheritsLoose(MessageState, _Context5);
        function MessageState() {
          return _Context5.apply(this, arguments) || this;
        }
        return MessageState;
      }(Context));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/suback.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "5937ag6U0JDV5qkoBNRUUnW", "suback", undefined);
      function encode(packet) {
        var packetType = 9;
        var flags = 0;
        return Uint8Array.from([(packetType << 4) + flags, 2 + packet.returnCodes.length, packet.id >> 8, packet.id & 0xff].concat(packet.returnCodes));
      }
      function decode(buffer, remainingStart, _remainingLength) {
        var idStart = remainingStart;
        var id = (buffer[idStart] << 8) + buffer[idStart + 1];
        var payloadStart = idStart + 2;
        var returnCodes = [];
        for (var i = payloadStart; i < buffer.length; i++) {
          returnCodes.push(buffer[i]);
        }
        return {
          type: "suback",
          id: id,
          returnCodes: returnCodes
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/subscribe.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './length.ts', './utf8.ts'], function (exports) {
  var _createForOfIteratorHelperLoose, cclegacy, encodeLength, encodeUTF8String, decodeUTF8String;
  return {
    setters: [function (module) {
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      encodeLength = module.encodeLength;
    }, function (module) {
      encodeUTF8String = module.encodeUTF8String;
      decodeUTF8String = module.decodeUTF8String;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "4c9b7DexxFD5q1qzNIYfQOl", "subscribe", undefined);
      function encode(packet, utf8Encoder) {
        var packetType = 8;
        var flags = 2; // bit 2 must be 1 in 3.1.1

        var variableHeader = [packet.id >> 8, packet.id & 0xff];
        var payload = [];
        for (var _iterator = _createForOfIteratorHelperLoose(packet.subscriptions), _step; !(_step = _iterator()).done;) {
          var sub = _step.value;
          payload.push.apply(payload, encodeUTF8String(sub.topicFilter, utf8Encoder).concat([sub.qos]));
        }
        var fixedHeader = [packetType << 4 | flags].concat(encodeLength(variableHeader.length + payload.length));
        return Uint8Array.from([].concat(fixedHeader, variableHeader, payload));
      }
      function decode(buffer, remainingStart, _remainingLength, utf8Decoder) {
        var idStart = remainingStart;
        var id = (buffer[idStart] << 8) + buffer[idStart + 1];
        var subscriptionsStart = idStart + 2;
        var subscriptions = [];
        for (var i = subscriptionsStart; i < buffer.length;) {
          var topicFilter = decodeUTF8String(buffer, i, utf8Decoder);
          i += topicFilter.length;
          var qos = buffer[i];
          i += 1;
          if (qos !== 0 && qos !== 1 && qos !== 2) {
            throw new Error("invalid qos");
          }
          subscriptions.push({
            topicFilter: topicFilter.value,
            qos: qos
          });
        }
        return {
          type: "subscribe",
          id: id,
          subscriptions: subscriptions
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/subtle_dsa.ts", ['cc', './errors.ts'], function (exports) {
  var cclegacy, JOSENotSupported;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      JOSENotSupported = module.JOSENotSupported;
    }],
    execute: function () {
      exports('default', subtleDsa);
      cclegacy._RF.push({}, "22272jTWK1A8qIeP11gbnh1", "subtle_dsa", undefined);
      function subtleDsa(alg, algorithm) {
        var hash = "SHA-" + alg.slice(-3);
        switch (alg) {
          case 'HS256':
          case 'HS384':
          case 'HS512':
            return {
              hash: hash,
              name: 'HMAC'
            };
          case 'PS256':
          case 'PS384':
          case 'PS512':
            // @ts-expect-error
            return {
              hash: hash,
              name: 'RSA-PSS',
              saltLength: alg.slice(-3) >> 3
            };
          case 'RS256':
          case 'RS384':
          case 'RS512':
            return {
              hash: hash,
              name: 'RSASSA-PKCS1-v1_5'
            };
          case 'ES256':
          case 'ES384':
          case 'ES512':
            return {
              hash: hash,
              name: 'ECDSA',
              namedCurve: algorithm.namedCurve
            };
          case 'EdDSA':
            return {
              name: algorithm.name
            };
          default:
            throw new JOSENotSupported("alg " + alg + " is not supported either by JOSE or your javascript runtime");
        }
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/tripledes.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js', './cipher-core.js'], function (exports) {
  var _inheritsLoose, cclegacy, WordArray, BlockCipher;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      WordArray = module.WordArray;
    }, function (module) {
      BlockCipher = module.BlockCipher;
    }],
    execute: function () {
      cclegacy._RF.push({}, "ba3b0clssBOEajVV2iyC+XL", "tripledes", undefined);

      // Permuted Choice 1 constants
      var PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];

      // Permuted Choice 2 constants
      var PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];

      // Cumulative bit shift constants
      var BIT_SHIFTS = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

      // SBOXes and round permutation constants
      var SBOX_P = [{
        0x0: 0x808200,
        0x10000000: 0x8000,
        0x20000000: 0x808002,
        0x30000000: 0x2,
        0x40000000: 0x200,
        0x50000000: 0x808202,
        0x60000000: 0x800202,
        0x70000000: 0x800000,
        0x80000000: 0x202,
        0x90000000: 0x800200,
        0xa0000000: 0x8200,
        0xb0000000: 0x808000,
        0xc0000000: 0x8002,
        0xd0000000: 0x800002,
        0xe0000000: 0x0,
        0xf0000000: 0x8202,
        0x8000000: 0x0,
        0x18000000: 0x808202,
        0x28000000: 0x8202,
        0x38000000: 0x8000,
        0x48000000: 0x808200,
        0x58000000: 0x200,
        0x68000000: 0x808002,
        0x78000000: 0x2,
        0x88000000: 0x800200,
        0x98000000: 0x8200,
        0xa8000000: 0x808000,
        0xb8000000: 0x800202,
        0xc8000000: 0x800002,
        0xd8000000: 0x8002,
        0xe8000000: 0x202,
        0xf8000000: 0x800000,
        0x1: 0x8000,
        0x10000001: 0x2,
        0x20000001: 0x808200,
        0x30000001: 0x800000,
        0x40000001: 0x808002,
        0x50000001: 0x8200,
        0x60000001: 0x200,
        0x70000001: 0x800202,
        0x80000001: 0x808202,
        0x90000001: 0x808000,
        0xa0000001: 0x800002,
        0xb0000001: 0x8202,
        0xc0000001: 0x202,
        0xd0000001: 0x800200,
        0xe0000001: 0x8002,
        0xf0000001: 0x0,
        0x8000001: 0x808202,
        0x18000001: 0x808000,
        0x28000001: 0x800000,
        0x38000001: 0x200,
        0x48000001: 0x8000,
        0x58000001: 0x800002,
        0x68000001: 0x2,
        0x78000001: 0x8202,
        0x88000001: 0x8002,
        0x98000001: 0x800202,
        0xa8000001: 0x202,
        0xb8000001: 0x808200,
        0xc8000001: 0x800200,
        0xd8000001: 0x0,
        0xe8000001: 0x8200,
        0xf8000001: 0x808002
      }, {
        0x0: 0x40084010,
        0x1000000: 0x4000,
        0x2000000: 0x80000,
        0x3000000: 0x40080010,
        0x4000000: 0x40000010,
        0x5000000: 0x40084000,
        0x6000000: 0x40004000,
        0x7000000: 0x10,
        0x8000000: 0x84000,
        0x9000000: 0x40004010,
        0xa000000: 0x40000000,
        0xb000000: 0x84010,
        0xc000000: 0x80010,
        0xd000000: 0x0,
        0xe000000: 0x4010,
        0xf000000: 0x40080000,
        0x800000: 0x40004000,
        0x1800000: 0x84010,
        0x2800000: 0x10,
        0x3800000: 0x40004010,
        0x4800000: 0x40084010,
        0x5800000: 0x40000000,
        0x6800000: 0x80000,
        0x7800000: 0x40080010,
        0x8800000: 0x80010,
        0x9800000: 0x0,
        0xa800000: 0x4000,
        0xb800000: 0x40080000,
        0xc800000: 0x40000010,
        0xd800000: 0x84000,
        0xe800000: 0x40084000,
        0xf800000: 0x4010,
        0x10000000: 0x0,
        0x11000000: 0x40080010,
        0x12000000: 0x40004010,
        0x13000000: 0x40084000,
        0x14000000: 0x40080000,
        0x15000000: 0x10,
        0x16000000: 0x84010,
        0x17000000: 0x4000,
        0x18000000: 0x4010,
        0x19000000: 0x80000,
        0x1a000000: 0x80010,
        0x1b000000: 0x40000010,
        0x1c000000: 0x84000,
        0x1d000000: 0x40004000,
        0x1e000000: 0x40000000,
        0x1f000000: 0x40084010,
        0x10800000: 0x84010,
        0x11800000: 0x80000,
        0x12800000: 0x40080000,
        0x13800000: 0x4000,
        0x14800000: 0x40004000,
        0x15800000: 0x40084010,
        0x16800000: 0x10,
        0x17800000: 0x40000000,
        0x18800000: 0x40084000,
        0x19800000: 0x40000010,
        0x1a800000: 0x40004010,
        0x1b800000: 0x80010,
        0x1c800000: 0x0,
        0x1d800000: 0x4010,
        0x1e800000: 0x40080010,
        0x1f800000: 0x84000
      }, {
        0x0: 0x104,
        0x100000: 0x0,
        0x200000: 0x4000100,
        0x300000: 0x10104,
        0x400000: 0x10004,
        0x500000: 0x4000004,
        0x600000: 0x4010104,
        0x700000: 0x4010000,
        0x800000: 0x4000000,
        0x900000: 0x4010100,
        0xa00000: 0x10100,
        0xb00000: 0x4010004,
        0xc00000: 0x4000104,
        0xd00000: 0x10000,
        0xe00000: 0x4,
        0xf00000: 0x100,
        0x80000: 0x4010100,
        0x180000: 0x4010004,
        0x280000: 0x0,
        0x380000: 0x4000100,
        0x480000: 0x4000004,
        0x580000: 0x10000,
        0x680000: 0x10004,
        0x780000: 0x104,
        0x880000: 0x4,
        0x980000: 0x100,
        0xa80000: 0x4010000,
        0xb80000: 0x10104,
        0xc80000: 0x10100,
        0xd80000: 0x4000104,
        0xe80000: 0x4010104,
        0xf80000: 0x4000000,
        0x1000000: 0x4010100,
        0x1100000: 0x10004,
        0x1200000: 0x10000,
        0x1300000: 0x4000100,
        0x1400000: 0x100,
        0x1500000: 0x4010104,
        0x1600000: 0x4000004,
        0x1700000: 0x0,
        0x1800000: 0x4000104,
        0x1900000: 0x4000000,
        0x1a00000: 0x4,
        0x1b00000: 0x10100,
        0x1c00000: 0x4010000,
        0x1d00000: 0x104,
        0x1e00000: 0x10104,
        0x1f00000: 0x4010004,
        0x1080000: 0x4000000,
        0x1180000: 0x104,
        0x1280000: 0x4010100,
        0x1380000: 0x0,
        0x1480000: 0x10004,
        0x1580000: 0x4000100,
        0x1680000: 0x100,
        0x1780000: 0x4010004,
        0x1880000: 0x10000,
        0x1980000: 0x4010104,
        0x1a80000: 0x10104,
        0x1b80000: 0x4000004,
        0x1c80000: 0x4000104,
        0x1d80000: 0x4010000,
        0x1e80000: 0x4,
        0x1f80000: 0x10100
      }, {
        0x0: 0x80401000,
        0x10000: 0x80001040,
        0x20000: 0x401040,
        0x30000: 0x80400000,
        0x40000: 0x0,
        0x50000: 0x401000,
        0x60000: 0x80000040,
        0x70000: 0x400040,
        0x80000: 0x80000000,
        0x90000: 0x400000,
        0xa0000: 0x40,
        0xb0000: 0x80001000,
        0xc0000: 0x80400040,
        0xd0000: 0x1040,
        0xe0000: 0x1000,
        0xf0000: 0x80401040,
        0x8000: 0x80001040,
        0x18000: 0x40,
        0x28000: 0x80400040,
        0x38000: 0x80001000,
        0x48000: 0x401000,
        0x58000: 0x80401040,
        0x68000: 0x0,
        0x78000: 0x80400000,
        0x88000: 0x1000,
        0x98000: 0x80401000,
        0xa8000: 0x400000,
        0xb8000: 0x1040,
        0xc8000: 0x80000000,
        0xd8000: 0x400040,
        0xe8000: 0x401040,
        0xf8000: 0x80000040,
        0x100000: 0x400040,
        0x110000: 0x401000,
        0x120000: 0x80000040,
        0x130000: 0x0,
        0x140000: 0x1040,
        0x150000: 0x80400040,
        0x160000: 0x80401000,
        0x170000: 0x80001040,
        0x180000: 0x80401040,
        0x190000: 0x80000000,
        0x1a0000: 0x80400000,
        0x1b0000: 0x401040,
        0x1c0000: 0x80001000,
        0x1d0000: 0x400000,
        0x1e0000: 0x40,
        0x1f0000: 0x1000,
        0x108000: 0x80400000,
        0x118000: 0x80401040,
        0x128000: 0x0,
        0x138000: 0x401000,
        0x148000: 0x400040,
        0x158000: 0x80000000,
        0x168000: 0x80001040,
        0x178000: 0x40,
        0x188000: 0x80000040,
        0x198000: 0x1000,
        0x1a8000: 0x80001000,
        0x1b8000: 0x80400040,
        0x1c8000: 0x1040,
        0x1d8000: 0x80401000,
        0x1e8000: 0x400000,
        0x1f8000: 0x401040
      }, {
        0x0: 0x80,
        0x1000: 0x1040000,
        0x2000: 0x40000,
        0x3000: 0x20000000,
        0x4000: 0x20040080,
        0x5000: 0x1000080,
        0x6000: 0x21000080,
        0x7000: 0x40080,
        0x8000: 0x1000000,
        0x9000: 0x20040000,
        0xa000: 0x20000080,
        0xb000: 0x21040080,
        0xc000: 0x21040000,
        0xd000: 0x0,
        0xe000: 0x1040080,
        0xf000: 0x21000000,
        0x800: 0x1040080,
        0x1800: 0x21000080,
        0x2800: 0x80,
        0x3800: 0x1040000,
        0x4800: 0x40000,
        0x5800: 0x20040080,
        0x6800: 0x21040000,
        0x7800: 0x20000000,
        0x8800: 0x20040000,
        0x9800: 0x0,
        0xa800: 0x21040080,
        0xb800: 0x1000080,
        0xc800: 0x20000080,
        0xd800: 0x21000000,
        0xe800: 0x1000000,
        0xf800: 0x40080,
        0x10000: 0x40000,
        0x11000: 0x80,
        0x12000: 0x20000000,
        0x13000: 0x21000080,
        0x14000: 0x1000080,
        0x15000: 0x21040000,
        0x16000: 0x20040080,
        0x17000: 0x1000000,
        0x18000: 0x21040080,
        0x19000: 0x21000000,
        0x1a000: 0x1040000,
        0x1b000: 0x20040000,
        0x1c000: 0x40080,
        0x1d000: 0x20000080,
        0x1e000: 0x0,
        0x1f000: 0x1040080,
        0x10800: 0x21000080,
        0x11800: 0x1000000,
        0x12800: 0x1040000,
        0x13800: 0x20040080,
        0x14800: 0x20000000,
        0x15800: 0x1040080,
        0x16800: 0x80,
        0x17800: 0x21040000,
        0x18800: 0x40080,
        0x19800: 0x21040080,
        0x1a800: 0x0,
        0x1b800: 0x21000000,
        0x1c800: 0x1000080,
        0x1d800: 0x40000,
        0x1e800: 0x20040000,
        0x1f800: 0x20000080
      }, {
        0x0: 0x10000008,
        0x100: 0x2000,
        0x200: 0x10200000,
        0x300: 0x10202008,
        0x400: 0x10002000,
        0x500: 0x200000,
        0x600: 0x200008,
        0x700: 0x10000000,
        0x800: 0x0,
        0x900: 0x10002008,
        0xa00: 0x202000,
        0xb00: 0x8,
        0xc00: 0x10200008,
        0xd00: 0x202008,
        0xe00: 0x2008,
        0xf00: 0x10202000,
        0x80: 0x10200000,
        0x180: 0x10202008,
        0x280: 0x8,
        0x380: 0x200000,
        0x480: 0x202008,
        0x580: 0x10000008,
        0x680: 0x10002000,
        0x780: 0x2008,
        0x880: 0x200008,
        0x980: 0x2000,
        0xa80: 0x10002008,
        0xb80: 0x10200008,
        0xc80: 0x0,
        0xd80: 0x10202000,
        0xe80: 0x202000,
        0xf80: 0x10000000,
        0x1000: 0x10002000,
        0x1100: 0x10200008,
        0x1200: 0x10202008,
        0x1300: 0x2008,
        0x1400: 0x200000,
        0x1500: 0x10000000,
        0x1600: 0x10000008,
        0x1700: 0x202000,
        0x1800: 0x202008,
        0x1900: 0x0,
        0x1a00: 0x8,
        0x1b00: 0x10200000,
        0x1c00: 0x2000,
        0x1d00: 0x10002008,
        0x1e00: 0x10202000,
        0x1f00: 0x200008,
        0x1080: 0x8,
        0x1180: 0x202000,
        0x1280: 0x200000,
        0x1380: 0x10000008,
        0x1480: 0x10002000,
        0x1580: 0x2008,
        0x1680: 0x10202008,
        0x1780: 0x10200000,
        0x1880: 0x10202000,
        0x1980: 0x10200008,
        0x1a80: 0x2000,
        0x1b80: 0x202008,
        0x1c80: 0x200008,
        0x1d80: 0x0,
        0x1e80: 0x10000000,
        0x1f80: 0x10002008
      }, {
        0x0: 0x100000,
        0x10: 0x2000401,
        0x20: 0x400,
        0x30: 0x100401,
        0x40: 0x2100401,
        0x50: 0x0,
        0x60: 0x1,
        0x70: 0x2100001,
        0x80: 0x2000400,
        0x90: 0x100001,
        0xa0: 0x2000001,
        0xb0: 0x2100400,
        0xc0: 0x2100000,
        0xd0: 0x401,
        0xe0: 0x100400,
        0xf0: 0x2000000,
        0x8: 0x2100001,
        0x18: 0x0,
        0x28: 0x2000401,
        0x38: 0x2100400,
        0x48: 0x100000,
        0x58: 0x2000001,
        0x68: 0x2000000,
        0x78: 0x401,
        0x88: 0x100401,
        0x98: 0x2000400,
        0xa8: 0x2100000,
        0xb8: 0x100001,
        0xc8: 0x400,
        0xd8: 0x2100401,
        0xe8: 0x1,
        0xf8: 0x100400,
        0x100: 0x2000000,
        0x110: 0x100000,
        0x120: 0x2000401,
        0x130: 0x2100001,
        0x140: 0x100001,
        0x150: 0x2000400,
        0x160: 0x2100400,
        0x170: 0x100401,
        0x180: 0x401,
        0x190: 0x2100401,
        0x1a0: 0x100400,
        0x1b0: 0x1,
        0x1c0: 0x0,
        0x1d0: 0x2100000,
        0x1e0: 0x2000001,
        0x1f0: 0x400,
        0x108: 0x100400,
        0x118: 0x2000401,
        0x128: 0x2100001,
        0x138: 0x1,
        0x148: 0x2000000,
        0x158: 0x100000,
        0x168: 0x401,
        0x178: 0x2100400,
        0x188: 0x2000001,
        0x198: 0x2100000,
        0x1a8: 0x0,
        0x1b8: 0x2100401,
        0x1c8: 0x100401,
        0x1d8: 0x400,
        0x1e8: 0x2000400,
        0x1f8: 0x100001
      }, {
        0x0: 0x8000820,
        0x1: 0x20000,
        0x2: 0x8000000,
        0x3: 0x20,
        0x4: 0x20020,
        0x5: 0x8020820,
        0x6: 0x8020800,
        0x7: 0x800,
        0x8: 0x8020000,
        0x9: 0x8000800,
        0xa: 0x20800,
        0xb: 0x8020020,
        0xc: 0x820,
        0xd: 0x0,
        0xe: 0x8000020,
        0xf: 0x20820,
        0x80000000: 0x800,
        0x80000001: 0x8020820,
        0x80000002: 0x8000820,
        0x80000003: 0x8000000,
        0x80000004: 0x8020000,
        0x80000005: 0x20800,
        0x80000006: 0x20820,
        0x80000007: 0x20,
        0x80000008: 0x8000020,
        0x80000009: 0x820,
        0x8000000a: 0x20020,
        0x8000000b: 0x8020800,
        0x8000000c: 0x0,
        0x8000000d: 0x8020020,
        0x8000000e: 0x8000800,
        0x8000000f: 0x20000,
        0x10: 0x20820,
        0x11: 0x8020800,
        0x12: 0x20,
        0x13: 0x800,
        0x14: 0x8000800,
        0x15: 0x8000020,
        0x16: 0x8020020,
        0x17: 0x20000,
        0x18: 0x0,
        0x19: 0x20020,
        0x1a: 0x8020000,
        0x1b: 0x8000820,
        0x1c: 0x8020820,
        0x1d: 0x20800,
        0x1e: 0x820,
        0x1f: 0x8000000,
        0x80000010: 0x20000,
        0x80000011: 0x800,
        0x80000012: 0x8020020,
        0x80000013: 0x20820,
        0x80000014: 0x20,
        0x80000015: 0x8020000,
        0x80000016: 0x8000000,
        0x80000017: 0x8000820,
        0x80000018: 0x8020820,
        0x80000019: 0x8000020,
        0x8000001a: 0x8000800,
        0x8000001b: 0x0,
        0x8000001c: 0x20800,
        0x8000001d: 0x820,
        0x8000001e: 0x20020,
        0x8000001f: 0x8020800
      }];

      // Masks that select the SBOX input
      var SBOX_MASK = [0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000, 0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f];

      // Swap bits across the left and right words
      function exchangeLR(offset, mask) {
        var t = (this._lBlock >>> offset ^ this._rBlock) & mask;
        this._rBlock ^= t;
        this._lBlock ^= t << offset;
      }
      function exchangeRL(offset, mask) {
        var t = (this._rBlock >>> offset ^ this._lBlock) & mask;
        this._lBlock ^= t;
        this._rBlock ^= t << offset;
      }

      /**
       * DES block cipher algorithm.
       */
      var DESAlgo = exports('DESAlgo', /*#__PURE__*/function (_BlockCipher) {
        _inheritsLoose(DESAlgo, _BlockCipher);
        function DESAlgo(xformMode, key, cfg) {
          var _this;
          _this = _BlockCipher.call(this, xformMode, key, cfg) || this;

          // blickSize is an instance field and should set in constructor.
          // Both DESAlgo and TripleDESAlgo.
          _this.blockSize = 64 / 32;
          return _this;
        }
        var _proto = DESAlgo.prototype;
        _proto._doReset = function _doReset() {
          // Shortcuts
          var key = this._key;
          var keyWords = key.words;

          // Select 56 bits according to PC1
          var keyBits = [];
          for (var i = 0; i < 56; i += 1) {
            var keyBitPos = PC1[i] - 1;
            keyBits[i] = keyWords[keyBitPos >>> 5] >>> 31 - keyBitPos % 32 & 1;
          }

          // Assemble 16 subkeys
          this._subKeys = [];
          var subKeys = this._subKeys;
          for (var nSubKey = 0; nSubKey < 16; nSubKey += 1) {
            // Create subkey
            subKeys[nSubKey] = [];
            var subKey = subKeys[nSubKey];

            // Shortcut
            var bitShift = BIT_SHIFTS[nSubKey];

            // Select 48 bits according to PC2
            for (var _i = 0; _i < 24; _i += 1) {
              // Select from the left 28 key bits
              subKey[_i / 6 | 0] |= keyBits[(PC2[_i] - 1 + bitShift) % 28] << 31 - _i % 6;

              // Select from the right 28 key bits
              subKey[4 + (_i / 6 | 0)] |= keyBits[28 + (PC2[_i + 24] - 1 + bitShift) % 28] << 31 - _i % 6;
            }

            // Since each subkey is applied to an expanded 32-bit input,
            // the subkey can be broken into 8 values scaled to 32-bits,
            // which allows the key to be used without expansion
            subKey[0] = subKey[0] << 1 | subKey[0] >>> 31;
            for (var _i2 = 1; _i2 < 7; _i2 += 1) {
              subKey[_i2] >>>= (_i2 - 1) * 4 + 3;
            }
            subKey[7] = subKey[7] << 5 | subKey[7] >>> 27;
          }

          // Compute inverse subkeys
          this._invSubKeys = [];
          var invSubKeys = this._invSubKeys;
          for (var _i3 = 0; _i3 < 16; _i3 += 1) {
            invSubKeys[_i3] = subKeys[15 - _i3];
          }
        };
        _proto.encryptBlock = function encryptBlock(M, offset) {
          this._doCryptBlock(M, offset, this._subKeys);
        };
        _proto.decryptBlock = function decryptBlock(M, offset) {
          this._doCryptBlock(M, offset, this._invSubKeys);
        };
        _proto._doCryptBlock = function _doCryptBlock(M, offset, subKeys) {
          var _M = M;

          // Get input
          this._lBlock = M[offset];
          this._rBlock = M[offset + 1];

          // Initial permutation
          exchangeLR.call(this, 4, 0x0f0f0f0f);
          exchangeLR.call(this, 16, 0x0000ffff);
          exchangeRL.call(this, 2, 0x33333333);
          exchangeRL.call(this, 8, 0x00ff00ff);
          exchangeLR.call(this, 1, 0x55555555);

          // Rounds
          for (var round = 0; round < 16; round += 1) {
            // Shortcuts
            var subKey = subKeys[round];
            var lBlock = this._lBlock;
            var rBlock = this._rBlock;

            // Feistel function
            var f = 0;
            for (var i = 0; i < 8; i += 1) {
              f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
            }
            this._lBlock = rBlock;
            this._rBlock = lBlock ^ f;
          }

          // Undo swap from last round
          var t = this._lBlock;
          this._lBlock = this._rBlock;
          this._rBlock = t;

          // Final permutation
          exchangeLR.call(this, 1, 0x55555555);
          exchangeRL.call(this, 8, 0x00ff00ff);
          exchangeRL.call(this, 2, 0x33333333);
          exchangeLR.call(this, 16, 0x0000ffff);
          exchangeLR.call(this, 4, 0x0f0f0f0f);

          // Set output
          _M[offset] = this._lBlock;
          _M[offset + 1] = this._rBlock;
        };
        return DESAlgo;
      }(BlockCipher));
      DESAlgo.keySize = 64 / 32;
      DESAlgo.ivSize = 64 / 32;
      // blickSize is an instance field and should set in constructor.

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
       */
      var DES = exports('DES', BlockCipher._createHelper(DESAlgo));

      /**
       * Triple-DES block cipher algorithm.
       */
      var TripleDESAlgo = exports('TripleDESAlgo', /*#__PURE__*/function (_BlockCipher2) {
        _inheritsLoose(TripleDESAlgo, _BlockCipher2);
        function TripleDESAlgo() {
          return _BlockCipher2.apply(this, arguments) || this;
        }
        var _proto2 = TripleDESAlgo.prototype;
        _proto2._doReset = function _doReset() {
          // Shortcuts
          var key = this._key;
          var keyWords = key.words;
          // Make sure the key length is valid (64, 128 or >= 192 bit)
          if (keyWords.length !== 2 && keyWords.length !== 4 && keyWords.length < 6) {
            throw new Error('Invalid key length - 3DES requires the key length to be 64, 128, 192 or >192.');
          }

          // Extend the key according to the keying options defined in 3DES standard
          var key1 = keyWords.slice(0, 2);
          var key2 = keyWords.length < 4 ? keyWords.slice(0, 2) : keyWords.slice(2, 4);
          var key3 = keyWords.length < 6 ? keyWords.slice(0, 2) : keyWords.slice(4, 6);

          // Create DES instances
          this._des1 = DESAlgo.createEncryptor(WordArray.create(key1));
          this._des2 = DESAlgo.createEncryptor(WordArray.create(key2));
          this._des3 = DESAlgo.createEncryptor(WordArray.create(key3));
        };
        _proto2.encryptBlock = function encryptBlock(M, offset) {
          this._des1.encryptBlock(M, offset);
          this._des2.decryptBlock(M, offset);
          this._des3.encryptBlock(M, offset);
        };
        _proto2.decryptBlock = function decryptBlock(M, offset) {
          this._des3.decryptBlock(M, offset);
          this._des2.encryptBlock(M, offset);
          this._des1.decryptBlock(M, offset);
        };
        return TripleDESAlgo;
      }(BlockCipher));
      TripleDESAlgo.keySize = 192 / 32;
      TripleDESAlgo.ivSize = 64 / 32;
      // blickSize is an instance field and should set in constructor.

      /**
       * Shortcut functions to the cipher's object interface.
       *
       * @example
       *
       *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
       *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
       */
      var TripleDES = exports('TripleDES', BlockCipher._createHelper(TripleDESAlgo));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/unsuback.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "68631JomRZKdr4LKEU1Wpue", "unsuback", undefined);
      function encode(packet) {
        var packetType = 11;
        var flags = 0;
        return Uint8Array.from([(packetType << 4) + flags, 2, packet.id >> 8, packet.id & 0xff]);
      }
      function decode(buffer, _remainingStart, _remainingLength) {
        var id = (buffer[2] << 8) + buffer[3];
        return {
          type: "unsuback",
          id: id
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/unsubscribe.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './length.ts', './utf8.ts'], function (exports) {
  var _createForOfIteratorHelperLoose, cclegacy, encodeLength, encodeUTF8String, decodeUTF8String;
  return {
    setters: [function (module) {
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      encodeLength = module.encodeLength;
    }, function (module) {
      encodeUTF8String = module.encodeUTF8String;
      decodeUTF8String = module.decodeUTF8String;
    }],
    execute: function () {
      exports({
        decode: decode,
        encode: encode
      });
      cclegacy._RF.push({}, "357aeo2tSFJBKzaPjYJgkgi", "unsubscribe", undefined);
      function encode(packet, utf8Encoder) {
        var packetType = 10;
        var flags = 2;
        var variableHeader = [packet.id >> 8, packet.id & 0xff];
        var payload = [];
        for (var _iterator = _createForOfIteratorHelperLoose(packet.topicFilters), _step; !(_step = _iterator()).done;) {
          var topic = _step.value;
          payload.push.apply(payload, encodeUTF8String(topic, utf8Encoder));
        }
        var fixedHeader = [packetType << 4 | flags].concat(encodeLength(variableHeader.length + payload.length));
        return Uint8Array.from([].concat(fixedHeader, variableHeader, payload));
      }
      function decode(buffer, remainingStart, _remainingLength, utf8Decoder) {
        var idStart = remainingStart;
        var id = (buffer[idStart] << 8) + buffer[idStart + 1];
        var topicFiltersStart = idStart + 2;
        var topicFilters = [];
        for (var i = topicFiltersStart; i < buffer.length;) {
          var topicFilter = decodeUTF8String(buffer, i, utf8Decoder);
          i += topicFilter.length;
          topicFilters.push(topicFilter.value);
        }
        return {
          type: "unsubscribe",
          id: id,
          topicFilters: topicFilters
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/utf8.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      exports({
        decodeUTF8String: decodeUTF8String,
        encodeUTF8String: encodeUTF8String
      });
      cclegacy._RF.push({}, "3147cAgp+dBo6p+9lViCcMM", "utf8", undefined); // Deno and browsers have global TextEncoder and TextDecoder classes, but
      // Node does not so we have to use an abstraction for working with UTF8.
      function encodeUTF8String(str, encoder) {
        var bytes = encoder.encode(str);
        return [bytes.length >> 8, bytes.length & 0xff].concat(bytes);
      }
      function decodeUTF8String(buffer, startIndex, utf8Decoder) {
        var length = (buffer[startIndex] << 8) + buffer[startIndex + 1];
        var bytes = buffer.slice(startIndex + 2, startIndex + 2 + length);
        var value = utf8Decoder.decode(bytes);
        return {
          length: length + 2,
          value: value
        };
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/validate_crit.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './errors.ts'], function (exports) {
  var _createForOfIteratorHelperLoose, cclegacy, JOSENotSupported;
  return {
    setters: [function (module) {
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      JOSENotSupported = module.JOSENotSupported;
    }],
    execute: function () {
      exports('default', validateCrit);
      cclegacy._RF.push({}, "32538BUKxdGjKxhBC3FEVt0", "validate_crit", undefined);
      function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
        if (joseHeader.crit !== undefined && (protectedHeader == null ? void 0 : protectedHeader.crit) === undefined) {
          throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
        }
        if (!protectedHeader || protectedHeader.crit === undefined) {
          return new Set();
        }
        if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some(function (input) {
          return typeof input !== 'string' || input.length === 0;
        })) {
          throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
        }
        var recognized;
        if (recognizedOption !== undefined) {
          recognized = new Map([].concat(Object.entries(recognizedOption), recognizedDefault.entries()));
        } else {
          recognized = recognizedDefault;
        }
        for (var _iterator = _createForOfIteratorHelperLoose(protectedHeader.crit), _step; !(_step = _iterator()).done;) {
          var parameter = _step.value;
          if (!recognized.has(parameter)) {
            throw new JOSENotSupported("Extension Header Parameter \"" + parameter + "\" is not recognized");
          }
          if (joseHeader[parameter] === undefined) {
            throw new Err("Extension Header Parameter \"" + parameter + "\" is missing");
          }
          if (recognized.get(parameter) && protectedHeader[parameter] === undefined) {
            throw new Err("Extension Header Parameter \"" + parameter + "\" MUST be integrity protected");
          }
        }
        return new Set(protectedHeader.crit);
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/webcrypto.ts", ['cc'], function (exports) {
  var cclegacy;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
    }],
    execute: function () {
      cclegacy._RF.push({}, "e8554rwRXhK9pTUtjBFnNNQ", "webcrypto", undefined);
      // export default crypto

      var isCryptoKey = exports('isCryptoKey', function isCryptoKey(key) {
        return key instanceof CryptoKey;
      });
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/x64-core.js", ['./rollupPluginModLoBabelHelpers.js', 'cc', './core.js'], function (exports) {
  var _inheritsLoose, cclegacy, Base, WordArray;
  return {
    setters: [function (module) {
      _inheritsLoose = module.inheritsLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
    }, function (module) {
      Base = module.Base;
      WordArray = module.WordArray;
    }],
    execute: function () {
      cclegacy._RF.push({}, "19eac+AcbhFablgBkTnuO/A", "x64-core", undefined);
      var X32WordArray = WordArray;

      /**
       * A 64-bit word.
       */
      var X64Word = exports('X64Word', /*#__PURE__*/function (_Base) {
        _inheritsLoose(X64Word, _Base);
        /**
         * Initializes a newly created 64-bit word.
         *
         * @param {number} high The high 32 bits.
         * @param {number} low The low 32 bits.
         *
         * @example
         *
         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
         */
        function X64Word(high, low) {
          var _this;
          _this = _Base.call(this) || this;
          _this.high = high;
          _this.low = low;
          return _this;
        }
        return X64Word;
      }(Base));

      /**
       * An array of 64-bit words.
       *
       * @property {Array} words The array of CryptoJS.x64.Word objects.
       * @property {number} sigBytes The number of significant bytes in this word array.
       */
      var X64WordArray = exports('X64WordArray', /*#__PURE__*/function (_Base2) {
        _inheritsLoose(X64WordArray, _Base2);
        /**
         * Initializes a newly created word array.
         *
         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
         *
         * @example
         *
         *     var wordArray = CryptoJS.x64.WordArray.create();
         *
         *     var wordArray = CryptoJS.x64.WordArray.create([
         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
         *     ]);
         *
         *     var wordArray = CryptoJS.x64.WordArray.create([
         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
         *     ], 10);
         */
        function X64WordArray(words, sigBytes) {
          var _this2;
          if (words === void 0) {
            words = [];
          }
          if (sigBytes === void 0) {
            sigBytes = words.length * 8;
          }
          _this2 = _Base2.call(this) || this;
          _this2.words = words;
          _this2.sigBytes = sigBytes;
          return _this2;
        }

        /**
         * Converts this 64-bit word array to a 32-bit word array.
         *
         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
         *
         * @example
         *
         *     var x32WordArray = x64WordArray.toX32();
         */
        var _proto = X64WordArray.prototype;
        _proto.toX32 = function toX32() {
          // Shortcuts
          var x64Words = this.words;
          var x64WordsLength = x64Words.length;

          // Convert
          var x32Words = [];
          for (var i = 0; i < x64WordsLength; i += 1) {
            var x64Word = x64Words[i];
            x32Words.push(x64Word.high);
            x32Words.push(x64Word.low);
          }
          return X32WordArray.create(x32Words, this.sigBytes);
        }

        /**
         * Creates a copy of this word array.
         *
         * @return {X64WordArray} The clone.
         *
         * @example
         *
         *     var clone = x64WordArray.clone();
         */;
        _proto.clone = function clone() {
          var clone = _Base2.prototype.clone.call(this);

          // Clone "words" array
          clone.words = this.words.slice(0);
          var words = clone.words;

          // Clone each X64Word object
          var wordsLength = words.length;
          for (var i = 0; i < wordsLength; i += 1) {
            words[i] = words[i].clone();
          }
          return clone;
        };
        return X64WordArray;
      }(Base));
      cclegacy._RF.pop();
    }
  };
});

(function(r) {
  r('virtual:///prerequisite-imports/main', 'chunks:///_virtual/main'); 
})(function(mid, cid) {
    System.register(mid, [cid], function (_export, _context) {
    return {
        setters: [function(_m) {
            var _exportObj = {};

            for (var _key in _m) {
              if (_key !== "default" && _key !== "__esModule") _exportObj[_key] = _m[_key];
            }
      
            _export(_exportObj);
        }],
        execute: function () { }
    };
    });
});