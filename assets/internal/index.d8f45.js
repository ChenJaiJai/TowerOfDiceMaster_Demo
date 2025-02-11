System.register("chunks:///_virtual/builtin-pipeline-settings.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './builtin-pipeline-types.ts'], function (exports) {
  var _applyDecoratedDescriptor, _inheritsLoose, _initializerDefineProperty, _assertThisInitialized, _createClass, cclegacy, _decorator, Camera, CCBoolean, CCInteger, CCFloat, Material, Texture2D, rendering, Component, fillRequiredPipelineSettings, makePipelineSettings;
  return {
    setters: [function (module) {
      _applyDecoratedDescriptor = module.applyDecoratedDescriptor;
      _inheritsLoose = module.inheritsLoose;
      _initializerDefineProperty = module.initializerDefineProperty;
      _assertThisInitialized = module.assertThisInitialized;
      _createClass = module.createClass;
    }, function (module) {
      cclegacy = module.cclegacy;
      _decorator = module._decorator;
      Camera = module.Camera;
      CCBoolean = module.CCBoolean;
      CCInteger = module.CCInteger;
      CCFloat = module.CCFloat;
      Material = module.Material;
      Texture2D = module.Texture2D;
      rendering = module.rendering;
      Component = module.Component;
    }, function (module) {
      fillRequiredPipelineSettings = module.fillRequiredPipelineSettings;
      makePipelineSettings = module.makePipelineSettings;
    }],
    execute: function () {
      var _dec, _dec2, _dec3, _dec4, _dec5, _dec6, _dec7, _dec8, _dec9, _dec10, _dec11, _dec12, _dec13, _dec14, _dec15, _dec16, _dec17, _dec18, _dec19, _dec20, _dec21, _dec22, _dec23, _dec24, _dec25, _dec26, _dec27, _dec28, _dec29, _dec30, _class, _class2, _descriptor, _descriptor2;
      cclegacy._RF.push({}, "de1c2EHcMhAIYRZY5nyTQHG", "builtin-pipeline-settings", undefined);
      var ccclass = _decorator.ccclass,
        disallowMultiple = _decorator.disallowMultiple,
        executeInEditMode = _decorator.executeInEditMode,
        menu = _decorator.menu,
        property = _decorator.property,
        requireComponent = _decorator.requireComponent,
        type = _decorator.type;
      var BuiltinPipelineSettings = exports('BuiltinPipelineSettings', (_dec = ccclass('BuiltinPipelineSettings'), _dec2 = menu('Rendering/BuiltinPipelineSettings'), _dec3 = requireComponent(Camera), _dec4 = property(CCBoolean), _dec5 = property({
        displayName: 'Editor Preview (Experimental)',
        type: CCBoolean
      }), _dec6 = property({
        group: {
          id: 'MSAA',
          name: 'Multisample Anti-Aliasing'
        },
        type: CCBoolean
      }), _dec7 = property({
        group: {
          id: 'MSAA',
          name: 'Multisample Anti-Aliasing',
          style: 'section'
        },
        type: CCInteger,
        range: [2, 4, 2]
      }), _dec8 = property({
        group: {
          id: 'ShadingScale',
          name: 'ShadingScale',
          style: 'section'
        },
        type: CCBoolean
      }), _dec9 = property({
        tooltip: 'i18n:postprocess.shadingScale',
        group: {
          id: 'ShadingScale',
          name: 'ShadingScale'
        },
        type: CCFloat,
        range: [0.01, 4, 0.01],
        slide: true
      }), _dec10 = property({
        group: {
          id: 'DepthOfField',
          name: 'DepthOfField (PostProcessing)',
          style: 'section'
        },
        type: CCBoolean,
        visible: false
      }), _dec11 = property({
        group: {
          id: 'DepthOfField',
          name: 'DepthOfField (PostProcessing)',
          style: 'section'
        },
        type: Material,
        visible: false
      }), _dec12 = property({
        group: {
          id: 'DepthOfField',
          name: 'DepthOfField (PostProcessing)',
          style: 'section'
        },
        type: CCFloat,
        min: 0,
        visible: false
      }), _dec13 = property({
        group: {
          id: 'DepthOfField',
          name: 'DepthOfField (PostProcessing)',
          style: 'section'
        },
        type: CCFloat,
        min: 0,
        visible: false
      }), _dec14 = type(CCFloat), _dec15 = property({
        group: {
          id: 'DepthOfField',
          name: 'DepthOfField (PostProcessing)',
          style: 'section'
        },
        type: CCFloat,
        range: [1, 10, 0.01],
        slide: true,
        visible: false
      }), _dec16 = property({
        group: {
          id: 'Bloom',
          name: 'Bloom (PostProcessing)',
          style: 'section'
        },
        type: CCBoolean
      }), _dec17 = property({
        group: {
          id: 'Bloom',
          name: 'Bloom (PostProcessing)',
          style: 'section'
        },
        type: Material
      }), _dec18 = property({
        tooltip: 'i18n:bloom.enableAlphaMask',
        group: {
          id: 'Bloom',
          name: 'Bloom (PostProcessing)',
          style: 'section'
        },
        type: CCBoolean
      }), _dec19 = property({
        tooltip: 'i18n:bloom.iterations',
        group: {
          id: 'Bloom',
          name: 'Bloom (PostProcessing)',
          style: 'section'
        },
        type: CCInteger,
        range: [1, 6, 1],
        slide: true
      }), _dec20 = property({
        tooltip: 'i18n:bloom.threshold',
        group: {
          id: 'Bloom',
          name: 'Bloom (PostProcessing)',
          style: 'section'
        },
        type: CCFloat,
        min: 0
      }), _dec21 = property({
        group: {
          id: 'Color Grading',
          name: 'ColorGrading (LDR) (PostProcessing)',
          style: 'section'
        },
        type: CCBoolean
      }), _dec22 = property({
        group: {
          id: 'Color Grading',
          name: 'ColorGrading (LDR) (PostProcessing)',
          style: 'section'
        },
        type: Material
      }), _dec23 = property({
        tooltip: 'i18n:color_grading.contribute',
        group: {
          id: 'Color Grading',
          name: 'ColorGrading (LDR) (PostProcessing)',
          style: 'section'
        },
        type: CCFloat,
        range: [0, 1, 0.01],
        slide: true
      }), _dec24 = property({
        tooltip: 'i18n:color_grading.originalMap',
        group: {
          id: 'Color Grading',
          name: 'ColorGrading (LDR) (PostProcessing)',
          style: 'section'
        },
        type: Texture2D
      }), _dec25 = property({
        group: {
          id: 'FXAA',
          name: 'Fast Approximate Anti-Aliasing (PostProcessing)',
          style: 'section'
        },
        type: CCBoolean
      }), _dec26 = property({
        group: {
          id: 'FXAA',
          name: 'Fast Approximate Anti-Aliasing (PostProcessing)',
          style: 'section'
        },
        type: Material
      }), _dec27 = property({
        group: {
          id: 'FSR',
          name: 'FidelityFX Super Resolution',
          style: 'section'
        },
        type: CCBoolean
      }), _dec28 = property({
        group: {
          id: 'FSR',
          name: 'FidelityFX Super Resolution',
          style: 'section'
        },
        type: Material
      }), _dec29 = property({
        group: {
          id: 'FSR',
          name: 'FidelityFX Super Resolution',
          style: 'section'
        },
        type: CCFloat,
        range: [0, 1, 0.01],
        slide: true
      }), _dec30 = property({
        group: {
          id: 'ToneMapping',
          name: 'ToneMapping',
          style: 'section'
        },
        type: Material
      }), _dec(_class = _dec2(_class = _dec3(_class = disallowMultiple(_class = executeInEditMode(_class = (_class2 = /*#__PURE__*/function (_Component) {
        _inheritsLoose(BuiltinPipelineSettings, _Component);
        function BuiltinPipelineSettings() {
          var _this;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          _this = _Component.call.apply(_Component, [this].concat(args)) || this;
          _initializerDefineProperty(_this, "_settings", _descriptor, _assertThisInitialized(_this));
          // Editor Preview
          _initializerDefineProperty(_this, "_editorPreview", _descriptor2, _assertThisInitialized(_this));
          return _this;
        }
        var _proto = BuiltinPipelineSettings.prototype;
        // Enable/Disable
        _proto.onEnable = function onEnable() {
          fillRequiredPipelineSettings(this._settings);
          var cameraComponent = this.getComponent(Camera);
          var camera = cameraComponent.camera;
          camera.pipelineSettings = this._settings;
        };
        _proto.onDisable = function onDisable() {
          var cameraComponent = this.getComponent(Camera);
          var camera = cameraComponent.camera;
          camera.pipelineSettings = null;
        };
        _proto._tryEnableEditorPreview = function _tryEnableEditorPreview() {
          if (rendering === undefined) {
            return;
          }
          if (this._editorPreview) {
            rendering.setEditorPipelineSettings(this._settings);
          } else {
            this._disableEditorPreview();
          }
        };
        _proto._disableEditorPreview = function _disableEditorPreview() {
          if (rendering === undefined) {
            return;
          }
          var current = rendering.getEditorPipelineSettings();
          if (current === this._settings) {
            rendering.setEditorPipelineSettings(null);
          }
        }

        // MSAA
        ;

        _createClass(BuiltinPipelineSettings, [{
          key: "editorPreview",
          get: function get() {
            return this._editorPreview;
          },
          set: function set(v) {
            this._editorPreview = v;
          }
        }, {
          key: "MsaaEnable",
          get: function get() {
            return this._settings.msaa.enabled;
          },
          set: function set(value) {
            this._settings.msaa.enabled = value;
          }
        }, {
          key: "msaaSampleCount",
          get: function get() {
            return this._settings.msaa.sampleCount;
          }

          // Shading Scale
          ,

          set: function set(value) {
            value = Math.pow(2, Math.ceil(Math.log2(Math.max(value, 2))));
            value = Math.min(value, 4);
            this._settings.msaa.sampleCount = value;
          }
        }, {
          key: "shadingScaleEnable",
          get: function get() {
            return this._settings.enableShadingScale;
          },
          set: function set(value) {
            this._settings.enableShadingScale = value;
          }
        }, {
          key: "shadingScale",
          get: function get() {
            return this._settings.shadingScale;
          }

          // DepthOfField
          ,

          set: function set(value) {
            this._settings.shadingScale = value;
          }
        }, {
          key: "dofEnable",
          get: function get() {
            return this._settings.depthOfField.enabled;
          },
          set: function set(value) {
            this._settings.depthOfField.enabled = value;
          }
        }, {
          key: "dofMaterial",
          get: function get() {
            return this._settings.depthOfField.material;
          },
          set: function set(value) {
            if (this._settings.depthOfField.material === value) {
              return;
            }
            this._settings.depthOfField.material = value;
          }
        }, {
          key: "dofFocusDistance",
          get: function get() {
            return this._settings.depthOfField.focusDistance;
          },
          set: function set(value) {
            this._settings.depthOfField.focusDistance = value;
          }
        }, {
          key: "dofFocusRange",
          get: function get() {
            return this._settings.depthOfField.focusRange;
          },
          set: function set(value) {
            this._settings.depthOfField.focusRange = value;
          }
        }, {
          key: "dofBokehRadius",
          get: function get() {
            return this._settings.depthOfField.bokehRadius;
          }

          // Bloom
          ,

          set: function set(value) {
            this._settings.depthOfField.bokehRadius = value;
          }
        }, {
          key: "bloomEnable",
          get: function get() {
            return this._settings.bloom.enabled;
          },
          set: function set(value) {
            this._settings.bloom.enabled = value;
          }
        }, {
          key: "bloomMaterial",
          get: function get() {
            return this._settings.bloom.material;
          },
          set: function set(value) {
            if (this._settings.bloom.material === value) {
              return;
            }
            this._settings.bloom.material = value;
          }
        }, {
          key: "bloomEnableAlphaMask",
          get: function get() {
            return this._settings.bloom.enableAlphaMask;
          },
          set: function set(value) {
            this._settings.bloom.enableAlphaMask = value;
          }
        }, {
          key: "bloomIterations",
          get: function get() {
            return this._settings.bloom.iterations;
          },
          set: function set(value) {
            this._settings.bloom.iterations = value;
          }
        }, {
          key: "bloomThreshold",
          get: function get() {
            return this._settings.bloom.threshold;
          },
          set: function set(value) {
            this._settings.bloom.threshold = value;
          }
        }, {
          key: "bloomIntensity",
          get: function get() {
            return this._settings.bloom.intensity;
          }

          // Color Grading (LDR)
          ,

          set: function set(value) {
            this._settings.bloom.intensity = value;
          }
        }, {
          key: "colorGradingEnable",
          get: function get() {
            return this._settings.colorGrading.enabled;
          },
          set: function set(value) {
            this._settings.colorGrading.enabled = value;
          }
        }, {
          key: "colorGradingMaterial",
          get: function get() {
            return this._settings.colorGrading.material;
          },
          set: function set(value) {
            if (this._settings.colorGrading.material === value) {
              return;
            }
            this._settings.colorGrading.material = value;
          }
        }, {
          key: "colorGradingContribute",
          get: function get() {
            return this._settings.colorGrading.contribute;
          },
          set: function set(value) {
            this._settings.colorGrading.contribute = value;
          }
        }, {
          key: "colorGradingMap",
          get: function get() {
            return this._settings.colorGrading.colorGradingMap;
          }

          // FXAA
          ,

          set: function set(val) {
            this._settings.colorGrading.colorGradingMap = val;
          }
        }, {
          key: "fxaaEnable",
          get: function get() {
            return this._settings.fxaa.enabled;
          },
          set: function set(value) {
            this._settings.fxaa.enabled = value;
          }
        }, {
          key: "fxaaMaterial",
          get: function get() {
            return this._settings.fxaa.material;
          }

          // FSR
          ,

          set: function set(value) {
            if (this._settings.fxaa.material === value) {
              return;
            }
            this._settings.fxaa.material = value;
          }
        }, {
          key: "fsrEnable",
          get: function get() {
            return this._settings.fsr.enabled;
          },
          set: function set(value) {
            this._settings.fsr.enabled = value;
          }
        }, {
          key: "fsrMaterial",
          get: function get() {
            return this._settings.fsr.material;
          },
          set: function set(value) {
            if (this._settings.fsr.material === value) {
              return;
            }
            this._settings.fsr.material = value;
          }
        }, {
          key: "fsrSharpness",
          get: function get() {
            return this._settings.fsr.sharpness;
          },
          set: function set(value) {
            this._settings.fsr.sharpness = value;
          }
        }, {
          key: "toneMappingMaterial",
          get: function get() {
            return this._settings.toneMapping.material;
          },
          set: function set(value) {
            if (this._settings.toneMapping.material === value) {
              return;
            }
            this._settings.toneMapping.material = value;
          }
        }]);
        return BuiltinPipelineSettings;
      }(Component), (_descriptor = _applyDecoratedDescriptor(_class2.prototype, "_settings", [property], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return makePipelineSettings();
        }
      }), _descriptor2 = _applyDecoratedDescriptor(_class2.prototype, "_editorPreview", [_dec4], {
        configurable: true,
        enumerable: true,
        writable: true,
        initializer: function initializer() {
          return false;
        }
      }), _applyDecoratedDescriptor(_class2.prototype, "editorPreview", [_dec5], Object.getOwnPropertyDescriptor(_class2.prototype, "editorPreview"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "MsaaEnable", [_dec6], Object.getOwnPropertyDescriptor(_class2.prototype, "MsaaEnable"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "msaaSampleCount", [_dec7], Object.getOwnPropertyDescriptor(_class2.prototype, "msaaSampleCount"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "shadingScaleEnable", [_dec8], Object.getOwnPropertyDescriptor(_class2.prototype, "shadingScaleEnable"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "shadingScale", [_dec9], Object.getOwnPropertyDescriptor(_class2.prototype, "shadingScale"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "dofEnable", [_dec10], Object.getOwnPropertyDescriptor(_class2.prototype, "dofEnable"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "dofMaterial", [_dec11], Object.getOwnPropertyDescriptor(_class2.prototype, "dofMaterial"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "dofFocusDistance", [_dec12], Object.getOwnPropertyDescriptor(_class2.prototype, "dofFocusDistance"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "dofFocusRange", [_dec13], Object.getOwnPropertyDescriptor(_class2.prototype, "dofFocusRange"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "dofBokehRadius", [_dec14, _dec15], Object.getOwnPropertyDescriptor(_class2.prototype, "dofBokehRadius"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "bloomEnable", [_dec16], Object.getOwnPropertyDescriptor(_class2.prototype, "bloomEnable"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "bloomMaterial", [_dec17], Object.getOwnPropertyDescriptor(_class2.prototype, "bloomMaterial"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "bloomEnableAlphaMask", [_dec18], Object.getOwnPropertyDescriptor(_class2.prototype, "bloomEnableAlphaMask"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "bloomIterations", [_dec19], Object.getOwnPropertyDescriptor(_class2.prototype, "bloomIterations"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "bloomThreshold", [_dec20], Object.getOwnPropertyDescriptor(_class2.prototype, "bloomThreshold"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "colorGradingEnable", [_dec21], Object.getOwnPropertyDescriptor(_class2.prototype, "colorGradingEnable"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "colorGradingMaterial", [_dec22], Object.getOwnPropertyDescriptor(_class2.prototype, "colorGradingMaterial"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "colorGradingContribute", [_dec23], Object.getOwnPropertyDescriptor(_class2.prototype, "colorGradingContribute"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "colorGradingMap", [_dec24], Object.getOwnPropertyDescriptor(_class2.prototype, "colorGradingMap"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "fxaaEnable", [_dec25], Object.getOwnPropertyDescriptor(_class2.prototype, "fxaaEnable"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "fxaaMaterial", [_dec26], Object.getOwnPropertyDescriptor(_class2.prototype, "fxaaMaterial"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "fsrEnable", [_dec27], Object.getOwnPropertyDescriptor(_class2.prototype, "fsrEnable"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "fsrMaterial", [_dec28], Object.getOwnPropertyDescriptor(_class2.prototype, "fsrMaterial"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "fsrSharpness", [_dec29], Object.getOwnPropertyDescriptor(_class2.prototype, "fsrSharpness"), _class2.prototype), _applyDecoratedDescriptor(_class2.prototype, "toneMappingMaterial", [_dec30], Object.getOwnPropertyDescriptor(_class2.prototype, "toneMappingMaterial"), _class2.prototype)), _class2)) || _class) || _class) || _class) || _class) || _class));
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/builtin-pipeline-types.ts", ['cc'], function (exports) {
  var cclegacy, gfx;
  return {
    setters: [function (module) {
      cclegacy = module.cclegacy;
      gfx = module.gfx;
    }],
    execute: function () {
      exports({
        fillRequiredBloom: fillRequiredBloom,
        fillRequiredColorGrading: fillRequiredColorGrading,
        fillRequiredDepthOfField: fillRequiredDepthOfField,
        fillRequiredFSR: fillRequiredFSR,
        fillRequiredFXAA: fillRequiredFXAA,
        fillRequiredHBAO: fillRequiredHBAO,
        fillRequiredMSAA: fillRequiredMSAA,
        fillRequiredPipelineSettings: fillRequiredPipelineSettings,
        fillRequiredToneMapping: fillRequiredToneMapping,
        makeBloom: makeBloom,
        makeColorGrading: makeColorGrading,
        makeDepthOfField: makeDepthOfField,
        makeFSR: makeFSR,
        makeFXAA: makeFXAA,
        makeHBAO: makeHBAO,
        makeMSAA: makeMSAA,
        makePipelineSettings: makePipelineSettings,
        makeToneMapping: makeToneMapping
      });
      cclegacy._RF.push({}, "cbf30kCUX9A3K+QpVC6wnzx", "builtin-pipeline-types", undefined);
      var SampleCount = gfx.SampleCount;
      function makeMSAA() {
        return {
          enabled: false,
          sampleCount: SampleCount.X4
        };
      }
      function fillRequiredMSAA(value) {
        if (value.enabled === undefined) {
          value.enabled = false;
        }
        if (value.sampleCount === undefined) {
          value.sampleCount = SampleCount.X4;
        }
      }
      function makeHBAO() {
        return {
          enabled: false,
          radiusScale: 1,
          angleBiasDegree: 10,
          blurSharpness: 3,
          aoSaturation: 1,
          needBlur: false
        };
      }
      function fillRequiredHBAO(value) {
        if (value.enabled === undefined) {
          value.enabled = false;
        }
        if (value.radiusScale === undefined) {
          value.radiusScale = 1;
        }
        if (value.angleBiasDegree === undefined) {
          value.angleBiasDegree = 10;
        }
        if (value.blurSharpness === undefined) {
          value.blurSharpness = 3;
        }
        if (value.aoSaturation === undefined) {
          value.aoSaturation = 1;
        }
        if (value.needBlur === undefined) {
          value.needBlur = false;
        }
      }
      function makeDepthOfField() {
        return {
          enabled: false,
          material: null,
          focusDistance: 0,
          focusRange: 0,
          bokehRadius: 1
        };
      }
      function fillRequiredDepthOfField(value) {
        if (value.enabled === undefined) {
          value.enabled = false;
        }
        if (value.material === undefined) {
          value.material = null;
        }
        if (value.focusDistance === undefined) {
          value.focusDistance = 0;
        }
        if (value.focusRange === undefined) {
          value.focusRange = 0;
        }
        if (value.bokehRadius === undefined) {
          value.bokehRadius = 1;
        }
      }
      function makeBloom() {
        return {
          enabled: false,
          material: null,
          enableAlphaMask: false,
          iterations: 3,
          threshold: 0.8,
          intensity: 2.3
        };
      }
      function fillRequiredBloom(value) {
        if (value.enabled === undefined) {
          value.enabled = false;
        }
        if (value.material === undefined) {
          value.material = null;
        }
        if (value.enableAlphaMask === undefined) {
          value.enableAlphaMask = false;
        }
        if (value.iterations === undefined) {
          value.iterations = 3;
        }
        if (value.threshold === undefined) {
          value.threshold = 0.8;
        }
        if (value.intensity === undefined) {
          value.intensity = 2.3;
        }
      }
      function makeColorGrading() {
        return {
          enabled: false,
          material: null,
          contribute: 1,
          colorGradingMap: null
        };
      }
      function fillRequiredColorGrading(value) {
        if (value.enabled === undefined) {
          value.enabled = false;
        }
        if (value.material === undefined) {
          value.material = null;
        }
        if (value.contribute === undefined) {
          value.contribute = 1;
        }
        if (value.colorGradingMap === undefined) {
          value.colorGradingMap = null;
        }
      }
      function makeFSR() {
        return {
          enabled: false,
          material: null,
          sharpness: 0.8
        };
      }
      function fillRequiredFSR(value) {
        if (value.enabled === undefined) {
          value.enabled = false;
        }
        if (value.material === undefined) {
          value.material = null;
        }
        if (value.sharpness === undefined) {
          value.sharpness = 0.8;
        }
      }
      function makeFXAA() {
        return {
          enabled: false,
          material: null
        };
      }
      function fillRequiredFXAA(value) {
        if (value.enabled === undefined) {
          value.enabled = false;
        }
        if (value.material === undefined) {
          value.material = null;
        }
      }
      function makeToneMapping() {
        return {
          material: null
        };
      }
      function fillRequiredToneMapping(value) {
        if (value.material === undefined) {
          value.material = null;
        }
      }
      function makePipelineSettings() {
        return {
          msaa: makeMSAA(),
          enableShadingScale: false,
          shadingScale: 0.5,
          depthOfField: makeDepthOfField(),
          bloom: makeBloom(),
          toneMapping: makeToneMapping(),
          colorGrading: makeColorGrading(),
          fsr: makeFSR(),
          fxaa: makeFXAA()
        };
      }
      function fillRequiredPipelineSettings(value) {
        if (!value.msaa) {
          value.msaa = makeMSAA();
        } else {
          fillRequiredMSAA(value.msaa);
        }
        if (value.enableShadingScale === undefined) {
          value.enableShadingScale = false;
        }
        if (value.shadingScale === undefined) {
          value.shadingScale = 0.5;
        }
        if (!value.depthOfField) {
          value.depthOfField = makeDepthOfField();
        } else {
          fillRequiredDepthOfField(value.depthOfField);
        }
        if (!value.bloom) {
          value.bloom = makeBloom();
        } else {
          fillRequiredBloom(value.bloom);
        }
        if (!value.toneMapping) {
          value.toneMapping = makeToneMapping();
        } else {
          fillRequiredToneMapping(value.toneMapping);
        }
        if (!value.colorGrading) {
          value.colorGrading = makeColorGrading();
        } else {
          fillRequiredColorGrading(value.colorGrading);
        }
        if (!value.fsr) {
          value.fsr = makeFSR();
        } else {
          fillRequiredFSR(value.fsr);
        }
        if (!value.fxaa) {
          value.fxaa = makeFXAA();
        } else {
          fillRequiredFXAA(value.fxaa);
        }
      }
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/builtin-pipeline.ts", ['./rollupPluginModLoBabelHelpers.js', 'cc', './builtin-pipeline-types.ts'], function () {
  var _createForOfIteratorHelperLoose, cclegacy, geometry, gfx, renderer, rendering, Vec3, Vec4, Vec2, Material, PipelineEventType, assert, warn, clamp, sys, pipeline, Layers, makePipelineSettings;
  return {
    setters: [function (module) {
      _createForOfIteratorHelperLoose = module.createForOfIteratorHelperLoose;
    }, function (module) {
      cclegacy = module.cclegacy;
      geometry = module.geometry;
      gfx = module.gfx;
      renderer = module.renderer;
      rendering = module.rendering;
      Vec3 = module.Vec3;
      Vec4 = module.Vec4;
      Vec2 = module.Vec2;
      Material = module.Material;
      PipelineEventType = module.PipelineEventType;
      assert = module.assert;
      warn = module.warn;
      clamp = module.clamp;
      sys = module.sys;
      pipeline = module.pipeline;
      Layers = module.Layers;
    }, function (module) {
      makePipelineSettings = module.makePipelineSettings;
    }],
    execute: function () {
      cclegacy._RF.push({}, "ff9b0GZzgRM/obMbHGfCNbk", "builtin-pipeline", undefined);
      var AABB = geometry.AABB,
        Sphere = geometry.Sphere,
        intersect = geometry.intersect;
      var ClearFlagBit = gfx.ClearFlagBit,
        Color = gfx.Color,
        Format = gfx.Format,
        FormatFeatureBit = gfx.FormatFeatureBit,
        LoadOp = gfx.LoadOp,
        StoreOp = gfx.StoreOp,
        TextureType = gfx.TextureType,
        Viewport = gfx.Viewport;
      var scene = renderer.scene;
      var CameraUsage = scene.CameraUsage,
        CSMLevel = scene.CSMLevel,
        LightType = scene.LightType;
      function forwardNeedClearColor(camera) {
        return !!(camera.clearFlag & (ClearFlagBit.COLOR | ClearFlagBit.STENCIL << 1));
      }
      function getCsmMainLightViewport(light, w, h, level, vp, screenSpaceSignY) {
        if (light.shadowFixedArea || light.csmLevel === CSMLevel.LEVEL_1) {
          vp.left = 0;
          vp.top = 0;
          vp.width = Math.trunc(w);
          vp.height = Math.trunc(h);
        } else {
          vp.left = Math.trunc(level % 2 * 0.5 * w);
          if (screenSpaceSignY > 0) {
            vp.top = Math.trunc((1 - Math.floor(level / 2)) * 0.5 * h);
          } else {
            vp.top = Math.trunc(Math.floor(level / 2) * 0.5 * h);
          }
          vp.width = Math.trunc(0.5 * w);
          vp.height = Math.trunc(0.5 * h);
        }
        vp.left = Math.max(0, vp.left);
        vp.top = Math.max(0, vp.top);
        vp.width = Math.max(1, vp.width);
        vp.height = Math.max(1, vp.height);
      }
      var PipelineConfigs = function PipelineConfigs() {
        this.isWeb = false;
        this.isWebGL1 = false;
        this.isWebGPU = false;
        this.isMobile = false;
        this.isHDR = false;
        this.useFloatOutput = false;
        this.toneMappingType = 0;
        // 0: ACES, 1: None
        this.shadowEnabled = false;
        this.shadowMapFormat = Format.R32F;
        this.shadowMapSize = new Vec2(1, 1);
        this.usePlanarShadow = false;
        this.screenSpaceSignY = 1;
        this.supportDepthSample = false;
        this.mobileMaxSpotLightShadowMaps = 1;
        this.platform = new Vec4(0, 0, 0, 0);
      };
      function setupPipelineConfigs(ppl, configs) {
        var sampleFeature = FormatFeatureBit.SAMPLED_TEXTURE | FormatFeatureBit.LINEAR_FILTER;
        var device = ppl.device;
        // Platform
        configs.isWeb = !sys.isNative;
        configs.isWebGL1 = device.gfxAPI === gfx.API.WEBGL;
        configs.isWebGPU = device.gfxAPI === gfx.API.WEBGPU;
        configs.isMobile = sys.isMobile;

        // Rendering
        configs.isHDR = ppl.pipelineSceneData.isHDR; // Has tone mapping
        configs.useFloatOutput = ppl.getMacroBool('CC_USE_FLOAT_OUTPUT');
        configs.toneMappingType = ppl.pipelineSceneData.postSettings.toneMappingType;
        // Shadow
        var shadowInfo = ppl.pipelineSceneData.shadows;
        configs.shadowEnabled = shadowInfo.enabled;
        configs.shadowMapFormat = pipeline.supportsR32FloatTexture(ppl.device) ? Format.R32F : Format.RGBA8;
        configs.shadowMapSize.set(shadowInfo.size);
        configs.usePlanarShadow = shadowInfo.enabled && shadowInfo.type === renderer.scene.ShadowType.Planar;
        // Device
        configs.screenSpaceSignY = ppl.device.capabilities.screenSpaceSignY;
        configs.supportDepthSample = (ppl.device.getFormatFeatures(Format.DEPTH_STENCIL) & sampleFeature) === sampleFeature;
        // Constants
        var screenSpaceSignY = device.capabilities.screenSpaceSignY;
        configs.platform.x = configs.isMobile ? 1.0 : 0.0;
        configs.platform.w = screenSpaceSignY * 0.5 + 0.5 << 1 | device.capabilities.clipSpaceSignY * 0.5 + 0.5;
      }
      var defaultSettings = makePipelineSettings();
      var CameraConfigs = function CameraConfigs() {
        this.colorName = '';
        this.depthStencilName = '';
        this.enableMainLightShadowMap = false;
        this.enableMainLightPlanarShadowMap = false;
        this.enablePostProcess = false;
        this.enableProfiler = false;
        this.enableShadingScale = false;
        this.enableMSAA = false;
        this.enableDOF = false;
        this.enableBloom = false;
        this.enableColorGrading = false;
        this.enableFXAA = false;
        this.enableFSR = false;
        this.enableHDR = false;
        this.enablePlanarReflectionProbe = false;
        this.useFullPipeline = false;
        this.singleForwardRadiancePass = false;
        this.radianceFormat = gfx.Format.RGBA8;
        this.shadingScale = 0.5;
        this.settings = defaultSettings;
      };
      function setupPostProcessConfigs(pipelineConfigs, settings, cameraConfigs) {
        cameraConfigs.enableDOF = pipelineConfigs.supportDepthSample && settings.depthOfField.enabled && !!settings.depthOfField.material;
        cameraConfigs.enableBloom = settings.bloom.enabled && !!settings.bloom.material;
        cameraConfigs.enableColorGrading = settings.colorGrading.enabled && !!settings.colorGrading.material && !!settings.colorGrading.colorGradingMap;
        cameraConfigs.enableFXAA = settings.fxaa.enabled && !!settings.fxaa.material;
        cameraConfigs.enablePostProcess = cameraConfigs.enableDOF || cameraConfigs.enableBloom || cameraConfigs.enableColorGrading || cameraConfigs.enableFXAA;
      }
      function setupCameraConfigs(camera, pipelineConfigs, cameraConfigs) {
        var window = camera.window;
        var isMainGameWindow = camera.cameraUsage === CameraUsage.GAME && !!window.swapchain;
        var isEditorView = camera.cameraUsage === CameraUsage.SCENE_VIEW || camera.cameraUsage === CameraUsage.PREVIEW;
        cameraConfigs.colorName = window.colorName;
        cameraConfigs.depthStencilName = window.depthStencilName;
        cameraConfigs.useFullPipeline = (camera.visibility & Layers.Enum.DEFAULT) !== 0;
        cameraConfigs.enableMainLightShadowMap = pipelineConfigs.shadowEnabled && !pipelineConfigs.usePlanarShadow && !!camera.scene && !!camera.scene.mainLight && camera.scene.mainLight.shadowEnabled;
        cameraConfigs.enableMainLightPlanarShadowMap = pipelineConfigs.shadowEnabled && pipelineConfigs.usePlanarShadow && !!camera.scene && !!camera.scene.mainLight && camera.scene.mainLight.shadowEnabled;
        cameraConfigs.enablePlanarReflectionProbe = isMainGameWindow || camera.cameraUsage === CameraUsage.SCENE_VIEW;
        cameraConfigs.enableProfiler = isMainGameWindow;
        cameraConfigs.settings = camera.pipelineSettings ? camera.pipelineSettings : defaultSettings;
        setupPostProcessConfigs(pipelineConfigs, cameraConfigs.settings, cameraConfigs);
        if (isEditorView) {
          var editorSettings = rendering.getEditorPipelineSettings();
          if (editorSettings) {
            cameraConfigs.settings = editorSettings;
            setupPostProcessConfigs(pipelineConfigs, cameraConfigs.settings, cameraConfigs);
          }
        }

        // MSAA
        cameraConfigs.enableMSAA = cameraConfigs.settings.msaa.enabled && !pipelineConfigs.isWeb // TODO(zhouzhenglong): remove this constraint
        && !pipelineConfigs.isWebGL1;

        // Shading scale
        cameraConfigs.shadingScale = cameraConfigs.settings.shadingScale;
        cameraConfigs.enableShadingScale = cameraConfigs.settings.enableShadingScale && cameraConfigs.shadingScale !== 1.0;

        // FSR (Depend on Shading scale)
        cameraConfigs.enableFSR = cameraConfigs.settings.fsr.enabled && !!cameraConfigs.settings.fsr.material && cameraConfigs.enableShadingScale && cameraConfigs.shadingScale < 1.0;

        // Forward rendering (Depend on MSAA and TBR)
        cameraConfigs.singleForwardRadiancePass = pipelineConfigs.isMobile || cameraConfigs.enableMSAA;
        cameraConfigs.enableHDR = cameraConfigs.useFullPipeline && pipelineConfigs.useFloatOutput;
        cameraConfigs.radianceFormat = cameraConfigs.enableHDR ? gfx.Format.RGBA16F : gfx.Format.RGBA8;
      }
      if (rendering) {
        var QueueHint = rendering.QueueHint,
          SceneFlags = rendering.SceneFlags,
          ResourceFlags = rendering.ResourceFlags,
          ResourceResidency = rendering.ResourceResidency;
        var ForwardLighting = /*#__PURE__*/function () {
          function ForwardLighting() {
            // Active lights
            this.lights = [];
            // Active spot lights with shadows (Mutually exclusive with `lights`)
            this.shadowEnabledSpotLights = [];
            // Internal cached resources
            this._sphere = Sphere.create(0, 0, 0, 1);
            this._boundingBox = new AABB();
            this._rangedDirLightBoundingBox = new AABB(0.0, 0.0, 0.0, 0.5, 0.5, 0.5);
          }
          var _proto = ForwardLighting.prototype;
          // ----------------------------------------------------------------
          // Interface
          // ----------------------------------------------------------------
          _proto.cullLights = function cullLights(scene, frustum, cameraPos) {
            // TODO(zhouzhenglong): Make light culling native
            this.lights.length = 0;
            this.shadowEnabledSpotLights.length = 0;
            // spot lights
            for (var _iterator = _createForOfIteratorHelperLoose(scene.spotLights), _step; !(_step = _iterator()).done;) {
              var light = _step.value;
              if (light.baked) {
                continue;
              }
              Sphere.set(this._sphere, light.position.x, light.position.y, light.position.z, light.range);
              if (intersect.sphereFrustum(this._sphere, frustum)) {
                if (light.shadowEnabled) {
                  this.shadowEnabledSpotLights.push(light);
                } else {
                  this.lights.push(light);
                }
              }
            }
            // sphere lights
            for (var _iterator2 = _createForOfIteratorHelperLoose(scene.sphereLights), _step2; !(_step2 = _iterator2()).done;) {
              var _light = _step2.value;
              if (_light.baked) {
                continue;
              }
              Sphere.set(this._sphere, _light.position.x, _light.position.y, _light.position.z, _light.range);
              if (intersect.sphereFrustum(this._sphere, frustum)) {
                this.lights.push(_light);
              }
            }
            // point lights
            for (var _iterator3 = _createForOfIteratorHelperLoose(scene.pointLights), _step3; !(_step3 = _iterator3()).done;) {
              var _light2 = _step3.value;
              if (_light2.baked) {
                continue;
              }
              Sphere.set(this._sphere, _light2.position.x, _light2.position.y, _light2.position.z, _light2.range);
              if (intersect.sphereFrustum(this._sphere, frustum)) {
                this.lights.push(_light2);
              }
            }
            // ranged dir lights
            for (var _iterator4 = _createForOfIteratorHelperLoose(scene.rangedDirLights), _step4; !(_step4 = _iterator4()).done;) {
              var _light3 = _step4.value;
              AABB.transform(this._boundingBox, this._rangedDirLightBoundingBox, _light3.node.getWorldMatrix());
              if (intersect.aabbFrustum(this._boundingBox, frustum)) {
                this.lights.push(_light3);
              }
            }
            if (cameraPos) {
              this.shadowEnabledSpotLights.sort(function (lhs, rhs) {
                return Vec3.squaredDistance(cameraPos, lhs.position) - Vec3.squaredDistance(cameraPos, rhs.position);
              });
            }
          };
          _proto._addLightQueues = function _addLightQueues(camera, pass) {
            for (var _iterator5 = _createForOfIteratorHelperLoose(this.lights), _step5; !(_step5 = _iterator5()).done;) {
              var light = _step5.value;
              var queue = pass.addQueue(QueueHint.BLEND, 'forward-add');
              switch (light.type) {
                case LightType.SPHERE:
                  queue.name = 'sphere-light';
                  break;
                case LightType.SPOT:
                  queue.name = 'spot-light';
                  break;
                case LightType.POINT:
                  queue.name = 'point-light';
                  break;
                case LightType.RANGED_DIRECTIONAL:
                  queue.name = 'ranged-directional-light';
                  break;
                default:
                  queue.name = 'unknown-light';
              }
              queue.addScene(camera, SceneFlags.BLEND, light);
            }
          };
          _proto.addSpotlightShadowPasses = function addSpotlightShadowPasses(ppl, camera, maxNumShadowMaps) {
            var i = 0;
            for (var _iterator6 = _createForOfIteratorHelperLoose(this.shadowEnabledSpotLights), _step6; !(_step6 = _iterator6()).done;) {
              var light = _step6.value;
              var shadowMapSize = ppl.pipelineSceneData.shadows.size;
              var shadowPass = ppl.addRenderPass(shadowMapSize.x, shadowMapSize.y, 'default');
              shadowPass.name = "SpotLightShadowPass" + i;
              shadowPass.addRenderTarget("SpotShadowMap" + i, LoadOp.CLEAR, StoreOp.STORE, new Color(1, 1, 1, 1));
              shadowPass.addDepthStencil("SpotShadowDepth" + i, LoadOp.CLEAR, StoreOp.DISCARD);
              shadowPass.addQueue(QueueHint.NONE, 'shadow-caster').addScene(camera, SceneFlags.OPAQUE | SceneFlags.MASK | SceneFlags.SHADOW_CASTER).useLightFrustum(light);
              ++i;
              if (i >= maxNumShadowMaps) {
                break;
              }
            }
          };
          _proto.addLightQueues = function addLightQueues(pass, camera, maxNumShadowMaps) {
            this._addLightQueues(camera, pass);
            var i = 0;
            for (var _iterator7 = _createForOfIteratorHelperLoose(this.shadowEnabledSpotLights), _step7; !(_step7 = _iterator7()).done;) {
              var light = _step7.value;
              // Add spot-light pass
              // Save last RenderPass to the `pass` variable
              // TODO(zhouzhenglong): Fix per queue addTexture
              pass.addTexture("SpotShadowMap" + i, 'cc_spotShadowMap');
              var queue = pass.addQueue(QueueHint.BLEND, 'forward-add');
              queue.addScene(camera, SceneFlags.BLEND, light);
              ++i;
              if (i >= maxNumShadowMaps) {
                break;
              }
            }
          }

          // Notice: ForwardLighting cannot handle a lot of lights.
          // If there are too many lights, the performance will be very poor.
          // If many lights are needed, please implement a forward+ or deferred rendering pipeline.
          ;

          _proto.addLightPasses = function addLightPasses(colorName, depthStencilName, depthStencilStoreOp, id,
          // window id
          width, height, camera, viewport, ppl, pass) {
            this._addLightQueues(camera, pass);
            var count = 0;
            var shadowMapSize = ppl.pipelineSceneData.shadows.size;
            for (var _iterator8 = _createForOfIteratorHelperLoose(this.shadowEnabledSpotLights), _step8; !(_step8 = _iterator8()).done;) {
              var light = _step8.value;
              var shadowPass = ppl.addRenderPass(shadowMapSize.x, shadowMapSize.y, 'default');
              shadowPass.name = 'SpotlightShadowPass';
              // Reuse csm shadow map
              shadowPass.addRenderTarget("ShadowMap" + id, LoadOp.CLEAR, StoreOp.STORE, new Color(1, 1, 1, 1));
              shadowPass.addDepthStencil("ShadowDepth" + id, LoadOp.CLEAR, StoreOp.DISCARD);
              shadowPass.addQueue(QueueHint.NONE, 'shadow-caster').addScene(camera, SceneFlags.OPAQUE | SceneFlags.MASK | SceneFlags.SHADOW_CASTER).useLightFrustum(light);

              // Add spot-light pass
              // Save last RenderPass to the `pass` variable
              ++count;
              var storeOp = count === this.shadowEnabledSpotLights.length ? depthStencilStoreOp : StoreOp.STORE;
              pass = ppl.addRenderPass(width, height, 'default');
              pass.name = 'SpotlightWithShadowMap';
              pass.setViewport(viewport);
              pass.addRenderTarget(colorName, LoadOp.LOAD);
              pass.addDepthStencil(depthStencilName, LoadOp.LOAD, storeOp);
              pass.addTexture("ShadowMap" + id, 'cc_spotShadowMap');
              var queue = pass.addQueue(QueueHint.BLEND, 'forward-add');
              queue.addScene(camera, SceneFlags.BLEND, light);
            }
            return pass;
          };
          _proto.isMultipleLightPassesNeeded = function isMultipleLightPassesNeeded() {
            return this.shadowEnabledSpotLights.length > 0;
          };
          return ForwardLighting;
        }();
        var BuiltinPipelineBuilder = /*#__PURE__*/function () {
          function BuiltinPipelineBuilder() {
            this._pipelineEvent = cclegacy.director.root.pipelineEvent;
            // Internal cached resources
            this._clearColor = new Color(0, 0, 0, 1);
            this._clearColorTransparentBlack = new Color(0, 0, 0, 0);
            this._reflectionProbeClearColor = new Vec3(0, 0, 0);
            this._viewport = new Viewport();
            this._configs = new PipelineConfigs();
            this._cameraConfigs = new CameraConfigs();
            // DepthOfField
            this._cocParams = new Vec4(0, 0, 0, 0);
            this._cocTexSize = new Vec4(0, 0, 0, 0);
            // Bloom
            this._bloomParams = new Vec4(0, 0, 0, 0);
            this._bloomTexSize = new Vec4(0, 0, 0, 0);
            this._bloomWidths = [];
            this._bloomHeights = [];
            this._bloomTexNames = [];
            // Color Grading
            this._colorGradingTexSize = new Vec2(0, 0);
            // FXAA
            this._fxaaParams = new Vec4(0, 0, 0, 0);
            // FSR
            this._fsrParams = new Vec4(0, 0, 0, 0);
            this._fsrTexSize = new Vec4(0, 0, 0, 0);
            // Materials
            this._copyAndTonemapMaterial = new Material();
            // Internal States
            this._initialized = false;
            // TODO(zhouzhenglong): Make default effect asset loading earlier and remove this flag
            // Forward lighting
            this.forwardLighting = new ForwardLighting();
          }
          var _proto2 = BuiltinPipelineBuilder.prototype;
          // ----------------------------------------------------------------
          // Interface
          // ----------------------------------------------------------------
          _proto2.windowResize = function windowResize(ppl, window, camera, nativeWidth, nativeHeight) {
            setupPipelineConfigs(ppl, this._configs);
            setupCameraConfigs(camera, this._configs, this._cameraConfigs);
            var settings = this._cameraConfigs.settings;
            var id = window.renderWindowId;
            var width = this._cameraConfigs.enableShadingScale ? Math.max(Math.floor(nativeWidth * this._cameraConfigs.shadingScale), 1) : nativeWidth;
            var height = this._cameraConfigs.enableShadingScale ? Math.max(Math.floor(nativeHeight * this._cameraConfigs.shadingScale), 1) : nativeHeight;

            // Render Window (UI)
            ppl.addRenderWindow(this._cameraConfigs.colorName, Format.RGBA8, nativeWidth, nativeHeight, window, this._cameraConfigs.depthStencilName);
            if (this._cameraConfigs.enableShadingScale) {
              ppl.addDepthStencil("ScaledSceneDepth" + id, Format.DEPTH_STENCIL, width, height);
              ppl.addRenderTarget("ScaledRadiance" + id, this._cameraConfigs.radianceFormat, width, height);
              ppl.addRenderTarget("ScaledLdrColor" + id, Format.RGBA8, width, height);
            } else {
              ppl.addDepthStencil("SceneDepth" + id, Format.DEPTH_STENCIL, width, height);
              ppl.addRenderTarget("Radiance" + id, this._cameraConfigs.radianceFormat, width, height);
              ppl.addRenderTarget("LdrColor" + id, Format.RGBA8, width, height);
            }
            if (this._cameraConfigs.enableFSR) {
              ppl.addRenderTarget("FsrColor" + id, Format.RGBA8, nativeWidth, nativeHeight);
            }

            // MsaaRadiance
            if (this._cameraConfigs.enableMSAA) {
              // Notice: We never store multisample results.
              // These samples are always resolved and discarded at the end of the render pass.
              // So the ResourceResidency should be MEMORYLESS.
              if (this._cameraConfigs.enableHDR) {
                ppl.addTexture("MsaaRadiance" + id, TextureType.TEX2D, this._cameraConfigs.radianceFormat, width, height, 1, 1, 1, settings.msaa.sampleCount, ResourceFlags.COLOR_ATTACHMENT, ResourceResidency.MEMORYLESS);
              } else {
                ppl.addTexture("MsaaRadiance" + id, TextureType.TEX2D, Format.RGBA8, width, height, 1, 1, 1, settings.msaa.sampleCount, ResourceFlags.COLOR_ATTACHMENT, ResourceResidency.MEMORYLESS);
              }
              ppl.addTexture("MsaaDepthStencil" + id, TextureType.TEX2D, Format.DEPTH_STENCIL, width, height, 1, 1, 1, settings.msaa.sampleCount, ResourceFlags.DEPTH_STENCIL_ATTACHMENT, ResourceResidency.MEMORYLESS);
            }

            // Mainlight ShadowMap
            ppl.addRenderTarget("ShadowMap" + id, this._configs.shadowMapFormat, this._configs.shadowMapSize.x, this._configs.shadowMapSize.y);
            ppl.addDepthStencil("ShadowDepth" + id, Format.DEPTH_STENCIL, this._configs.shadowMapSize.x, this._configs.shadowMapSize.y);

            // Spot-light shadow maps
            if (this._cameraConfigs.singleForwardRadiancePass) {
              var count = this._configs.mobileMaxSpotLightShadowMaps;
              for (var i = 0; i !== count; ++i) {
                ppl.addRenderTarget("SpotShadowMap" + i, this._configs.shadowMapFormat, this._configs.shadowMapSize.x, this._configs.shadowMapSize.y);
                ppl.addDepthStencil("SpotShadowDepth" + i, Format.DEPTH_STENCIL, this._configs.shadowMapSize.x, this._configs.shadowMapSize.y);
              }
            }

            // ---------------------------------------------------------
            // Post Process
            // ---------------------------------------------------------
            // DepthOfField
            if (this._cameraConfigs.enableDOF) {
              var halfWidth = Math.max(Math.floor(width / 2), 1);
              var halfHeight = Math.max(Math.floor(height / 2), 1);
              // `DofCoc${id}` texture will reuse ldrColorName
              ppl.addRenderTarget("DofRadiance" + id, this._cameraConfigs.radianceFormat, width, height);
              ppl.addRenderTarget("DofPrefilter" + id, this._cameraConfigs.radianceFormat, halfWidth, halfHeight);
              ppl.addRenderTarget("DofBokeh" + id, this._cameraConfigs.radianceFormat, halfWidth, halfHeight);
              ppl.addRenderTarget("DofFilter" + id, this._cameraConfigs.radianceFormat, halfWidth, halfHeight);
            }
            // Bloom (Kawase Dual Filter)
            if (this._cameraConfigs.enableBloom) {
              var bloomWidth = width;
              var bloomHeight = height;
              for (var _i = 0; _i !== settings.bloom.iterations + 1; ++_i) {
                bloomWidth = Math.max(Math.floor(bloomWidth / 2), 1);
                bloomHeight = Math.max(Math.floor(bloomHeight / 2), 1);
                ppl.addRenderTarget("BloomTex" + id + "_" + _i, this._cameraConfigs.radianceFormat, bloomWidth, bloomHeight);
              }
            }
            // Color Grading
            if (this._cameraConfigs.enableColorGrading && settings.colorGrading.material && settings.colorGrading.colorGradingMap) {
              settings.colorGrading.material.setProperty('colorGradingMap', settings.colorGrading.colorGradingMap);
            }
            // FXAA
            if (this._cameraConfigs.enableFXAA && this._cameraConfigs.enableShadingScale) {
              ppl.addRenderTarget("AaColor" + id, Format.RGBA8, width, height);
            }
          };
          _proto2.setup = function setup(cameras, ppl) {
            // TODO(zhouzhenglong): Make default effect asset loading earlier and remove _initMaterials
            if (this._initMaterials(ppl)) {
              return;
            }
            // Render cameras
            // log(`==================== One Frame ====================`);
            for (var _iterator9 = _createForOfIteratorHelperLoose(cameras), _step9; !(_step9 = _iterator9()).done;) {
              var camera = _step9.value;
              // Skip invalid camera
              if (!camera.scene || !camera.window) {
                continue;
              }
              // Setup camera configs
              setupCameraConfigs(camera, this._configs, this._cameraConfigs);
              // log(`Setup camera: ${camera.node!.name}, window: ${camera.window.renderWindowId}, isFull: ${this._cameraConfigs.useFullPipeline}, `
              //     + `size: ${camera.window.width}x${camera.window.height}`);

              this._pipelineEvent.emit(PipelineEventType.RENDER_CAMERA_BEGIN, camera);

              // Build pipeline
              if (this._cameraConfigs.useFullPipeline) {
                this._buildForwardPipeline(ppl, camera, camera.scene);
              } else {
                this._buildSimplePipeline(ppl, camera);
              }
              this._pipelineEvent.emit(PipelineEventType.RENDER_CAMERA_END, camera);
            }
          }

          // ----------------------------------------------------------------
          // Pipelines
          // ----------------------------------------------------------------
          ;

          _proto2._buildSimplePipeline = function _buildSimplePipeline(ppl, camera) {
            var width = Math.max(Math.floor(camera.window.width), 1);
            var height = Math.max(Math.floor(camera.window.height), 1);
            var colorName = this._cameraConfigs.colorName;
            var depthStencilName = this._cameraConfigs.depthStencilName;
            var viewport = camera.viewport; // Reduce C++/TS interop
            this._viewport.left = Math.round(viewport.x * width);
            this._viewport.top = Math.round(viewport.y * height);
            // Here we must use camera.viewport.width instead of camera.viewport.z, which
            // is undefined on native platform. The same as camera.viewport.height.
            this._viewport.width = Math.max(Math.round(viewport.width * width), 1);
            this._viewport.height = Math.max(Math.round(viewport.height * height), 1);
            var clearColor = camera.clearColor; // Reduce C++/TS interop
            this._clearColor.x = clearColor.x;
            this._clearColor.y = clearColor.y;
            this._clearColor.z = clearColor.z;
            this._clearColor.w = clearColor.w;
            var pass = ppl.addRenderPass(width, height, 'default');

            // bind output render target
            if (forwardNeedClearColor(camera)) {
              pass.addRenderTarget(colorName, LoadOp.CLEAR, StoreOp.STORE, this._clearColor);
            } else {
              pass.addRenderTarget(colorName, LoadOp.LOAD, StoreOp.STORE);
            }

            // bind depth stencil buffer
            if (camera.clearFlag & ClearFlagBit.DEPTH_STENCIL) {
              pass.addDepthStencil(depthStencilName, LoadOp.CLEAR, StoreOp.DISCARD, camera.clearDepth, camera.clearStencil, camera.clearFlag & ClearFlagBit.DEPTH_STENCIL);
            } else {
              pass.addDepthStencil(depthStencilName, LoadOp.LOAD, StoreOp.DISCARD);
            }
            pass.setViewport(this._viewport);

            // The opaque queue is used for Reflection probe preview
            pass.addQueue(QueueHint.OPAQUE).addScene(camera, SceneFlags.OPAQUE);

            // The blend queue is used for UI and Gizmos
            var flags = SceneFlags.BLEND | SceneFlags.UI;
            if (this._cameraConfigs.enableProfiler) {
              flags |= SceneFlags.PROFILER;
              pass.showStatistics = true;
            }
            pass.addQueue(QueueHint.BLEND).addScene(camera, flags);
          };
          _proto2._buildForwardPipeline = function _buildForwardPipeline(ppl, camera, scene) {
            // Init
            var settings = this._cameraConfigs.settings;
            var nativeWidth = Math.max(Math.floor(camera.window.width), 1);
            var nativeHeight = Math.max(Math.floor(camera.window.height), 1);
            var width = this._cameraConfigs.enableShadingScale ? Math.max(Math.floor(nativeWidth * this._cameraConfigs.shadingScale), 1) : nativeWidth;
            var height = this._cameraConfigs.enableShadingScale ? Math.max(Math.floor(nativeHeight * this._cameraConfigs.shadingScale), 1) : nativeHeight;
            var id = camera.window.renderWindowId;
            var colorName = this._cameraConfigs.colorName;
            var sceneDepth = this._cameraConfigs.enableShadingScale ? "ScaledSceneDepth" + id : "SceneDepth" + id;
            var radianceName = this._cameraConfigs.enableShadingScale ? "ScaledRadiance" + id : "Radiance" + id;
            var ldrColorName = this._cameraConfigs.enableShadingScale ? "ScaledLdrColor" + id : "LdrColor" + id;
            var mainLight = scene.mainLight;

            // Forward Lighting (Light Culling)
            this.forwardLighting.cullLights(scene, camera.frustum);

            // Main Directional light CSM Shadow Map
            if (this._cameraConfigs.enableMainLightShadowMap) {
              assert(!!mainLight);
              this._addCascadedShadowMapPass(ppl, id, mainLight, camera);
            }

            // Spot light shadow maps (Mobile or MSAA)
            if (this._cameraConfigs.singleForwardRadiancePass) {
              // Currently, only support 1 spot light with shadow map on mobile platform.
              // TODO(zhouzhenglong): Relex this limitation.
              this.forwardLighting.addSpotlightShadowPasses(ppl, camera, this._configs.mobileMaxSpotLightShadowMaps);
            }
            this._tryAddReflectionProbePasses(ppl, id, mainLight, camera.scene);

            // Forward Lighting
            var lastPass;
            if (this._cameraConfigs.enablePostProcess) {
              // Post Process
              // Radiance and DoF
              if (this._cameraConfigs.enableDOF) {
                assert(!!settings.depthOfField.material);
                var dofRadianceName = "DofRadiance" + id;
                // Disable MSAA, depth stencil cannot be resolved cross-platformly
                this._addForwardRadiancePasses(ppl, id, camera, width, height, mainLight, dofRadianceName, sceneDepth, true, StoreOp.STORE);
                this._addDepthOfFieldPasses(ppl, settings, settings.depthOfField.material, id, camera, width, height, dofRadianceName, sceneDepth, radianceName, ldrColorName);
              } else {
                this._addForwardRadiancePasses(ppl, id, camera, width, height, mainLight, radianceName, sceneDepth);
              }
              // Bloom
              if (this._cameraConfigs.enableBloom) {
                assert(!!settings.bloom.material);
                this._addKawaseDualFilterBloomPasses(ppl, settings, settings.bloom.material, id, width, height, radianceName);
              }
              // Tone Mapping and FXAA
              if (this._cameraConfigs.enableFXAA) {
                assert(!!settings.fxaa.material);
                var copyAndTonemapPassNeeded = this._cameraConfigs.enableHDR || this._cameraConfigs.enableColorGrading;
                var ldrColorBufferName = copyAndTonemapPassNeeded ? ldrColorName : radianceName;
                // FXAA is applied after tone mapping
                if (copyAndTonemapPassNeeded) {
                  this._addCopyAndTonemapPass(ppl, settings, width, height, radianceName, ldrColorBufferName);
                }
                // Apply FXAA
                if (this._cameraConfigs.enableShadingScale) {
                  var aaColorName = "AaColor" + id;
                  // Apply FXAA on scaled image
                  this._addFxaaPass(ppl, settings.fxaa.material, width, height, ldrColorBufferName, aaColorName);
                  // Copy FXAA result to screen
                  if (this._cameraConfigs.enableFSR && settings.fsr.material) {
                    // Apply FSR
                    lastPass = this._addFsrPass(ppl, settings, settings.fsr.material, id, width, height, aaColorName, nativeWidth, nativeHeight, colorName);
                  } else {
                    // Scale FXAA result to screen
                    lastPass = this._addCopyPass(ppl, nativeWidth, nativeHeight, aaColorName, colorName);
                  }
                } else {
                  // Image not scaled, output FXAA result to screen directly
                  lastPass = this._addFxaaPass(ppl, settings.fxaa.material, nativeWidth, nativeHeight, ldrColorBufferName, colorName);
                }
              } else {
                // No FXAA (Size might be scaled)
                lastPass = this._addTonemapResizeOrSuperResolutionPasses(ppl, settings, id, width, height, radianceName, ldrColorName, nativeWidth, nativeHeight, colorName);
              }
            } else if (this._cameraConfigs.enableHDR || this._cameraConfigs.enableShadingScale) {
              // HDR or Scaled LDR
              this._addForwardRadiancePasses(ppl, id, camera, width, height, mainLight, radianceName, sceneDepth);
              lastPass = this._addTonemapResizeOrSuperResolutionPasses(ppl, settings, id, width, height, radianceName, ldrColorName, nativeWidth, nativeHeight, colorName);
            } else {
              // LDR (Size is not scaled)
              lastPass = this._addForwardRadiancePasses(ppl, id, camera, nativeWidth, nativeHeight, mainLight, colorName, this._cameraConfigs.depthStencilName);
            }

            // UI size is not scaled, does not have AA
            this._addUIQueue(camera, lastPass);
          }

          // ----------------------------------------------------------------
          // Common Passes
          // ----------------------------------------------------------------
          ;

          _proto2._addTonemapResizeOrSuperResolutionPasses = function _addTonemapResizeOrSuperResolutionPasses(ppl, settings, id, width, height, radianceName, ldrColorName, nativeWidth, nativeHeight, colorName) {
            var lastPass;
            if (this._cameraConfigs.enableFSR && settings.fsr.material) {
              // Apply FSR
              this._addCopyAndTonemapPass(ppl, settings, width, height, radianceName, ldrColorName);
              lastPass = this._addFsrPass(ppl, settings, settings.fsr.material, id, width, height, ldrColorName, nativeWidth, nativeHeight, colorName);
            } else {
              // Output HDR/LDR result to screen directly (Size might be scaled)
              lastPass = this._addCopyAndTonemapPass(ppl, settings, nativeWidth, nativeHeight, radianceName, colorName);
            }
            return lastPass;
          };
          _proto2._addCascadedShadowMapPass = function _addCascadedShadowMapPass(ppl, id, light, camera) {
            // ----------------------------------------------------------------
            // Dynamic states
            // ----------------------------------------------------------------
            var width = ppl.pipelineSceneData.shadows.size.x;
            var height = ppl.pipelineSceneData.shadows.size.y;
            this._viewport.left = 0;
            this._viewport.top = 0;
            this._viewport.width = width;
            this._viewport.height = height;

            // ----------------------------------------------------------------
            // CSM Shadow Map
            // ----------------------------------------------------------------
            var pass = ppl.addRenderPass(width, height, 'default');
            pass.name = 'CascadedShadowMap';
            pass.addRenderTarget("ShadowMap" + id, LoadOp.CLEAR, StoreOp.STORE, new Color(1, 1, 1, 1));
            pass.addDepthStencil("ShadowDepth" + id, LoadOp.CLEAR, StoreOp.DISCARD);
            var csmLevel = ppl.pipelineSceneData.csmSupported ? light.csmLevel : 1;

            // Add shadow map viewports
            for (var level = 0; level !== csmLevel; ++level) {
              getCsmMainLightViewport(light, width, height, level, this._viewport, this._configs.screenSpaceSignY);
              var queue = pass.addQueue(QueueHint.NONE, 'shadow-caster');
              if (!this._configs.isWebGPU) {
                // Temporary workaround for WebGPU
                queue.setViewport(this._viewport);
              }
              queue.addScene(camera, SceneFlags.OPAQUE | SceneFlags.MASK | SceneFlags.SHADOW_CASTER).useLightFrustum(light, level);
            }
          };
          _proto2._addCopyPass = function _addCopyPass(ppl, width, height, input, output) {
            var pass = ppl.addRenderPass(width, height, 'cc-tone-mapping');
            pass.addRenderTarget(output, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            pass.addTexture(input, 'inputTexture');
            pass.setVec4('g_platform', this._configs.platform);
            pass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(this._copyAndTonemapMaterial, 1);
            return pass;
          };
          _proto2._addCopyAndTonemapPass = function _addCopyAndTonemapPass(ppl, settings, width, height, radianceName, colorName) {
            var pass;
            if (this._cameraConfigs.enableColorGrading && settings.colorGrading.material && settings.colorGrading.colorGradingMap) {
              var lutTex = settings.colorGrading.colorGradingMap;
              this._colorGradingTexSize.x = lutTex.width;
              this._colorGradingTexSize.y = lutTex.height;
              var isSquareMap = lutTex.width === lutTex.height;
              if (isSquareMap) {
                pass = ppl.addRenderPass(width, height, 'cc-color-grading-8x8');
              } else {
                pass = ppl.addRenderPass(width, height, 'cc-color-grading-nx1');
              }
              pass.addRenderTarget(colorName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
              pass.addTexture(radianceName, 'sceneColorMap');
              pass.setVec4('g_platform', this._configs.platform);
              pass.setVec2('lutTextureSize', this._colorGradingTexSize);
              pass.setFloat('contribute', settings.colorGrading.contribute);
              pass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(settings.colorGrading.material, isSquareMap ? 1 : 0);
            } else {
              pass = ppl.addRenderPass(width, height, 'cc-tone-mapping');
              pass.addRenderTarget(colorName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
              pass.addTexture(radianceName, 'inputTexture');
              pass.setVec4('g_platform', this._configs.platform);
              if (settings.toneMapping.material) {
                pass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(settings.toneMapping.material, 0);
              } else {
                pass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(this._copyAndTonemapMaterial, 0);
              }
            }
            return pass;
          };
          _proto2._buildForwardMainLightPass = function _buildForwardMainLightPass(pass, id, camera, colorName, depthStencilName, depthStencilStoreOp, mainLight, scene) {
            if (scene === void 0) {
              scene = null;
            }
            // set viewport
            pass.setViewport(this._viewport);
            var colorStoreOp = this._cameraConfigs.enableMSAA ? StoreOp.DISCARD : StoreOp.STORE;

            // bind output render target
            if (forwardNeedClearColor(camera)) {
              pass.addRenderTarget(colorName, LoadOp.CLEAR, colorStoreOp, this._clearColor);
            } else {
              pass.addRenderTarget(colorName, LoadOp.LOAD, colorStoreOp);
            }

            // bind depth stencil buffer
            {
              if (colorName === this._cameraConfigs.colorName && depthStencilName !== this._cameraConfigs.depthStencilName) {
                warn('Default framebuffer cannot use custom depth stencil buffer');
              }
            }
            if (camera.clearFlag & ClearFlagBit.DEPTH_STENCIL) {
              pass.addDepthStencil(depthStencilName, LoadOp.CLEAR, depthStencilStoreOp, camera.clearDepth, camera.clearStencil, camera.clearFlag & ClearFlagBit.DEPTH_STENCIL);
            } else {
              pass.addDepthStencil(depthStencilName, LoadOp.LOAD, depthStencilStoreOp);
            }

            // Set shadow map if enabled
            if (this._cameraConfigs.enableMainLightShadowMap) {
              pass.addTexture("ShadowMap" + id, 'cc_shadowMap');
            }

            // TODO(zhouzhenglong): Separate OPAQUE and MASK queue

            // add opaque and mask queue
            pass.addQueue(QueueHint.NONE) // Currently we put OPAQUE and MASK into one queue, so QueueHint is NONE
            .addScene(camera, SceneFlags.OPAQUE | SceneFlags.MASK, mainLight || undefined, scene ? scene : undefined);
          };
          _proto2._addDepthOfFieldPasses = function _addDepthOfFieldPasses(ppl, settings, dofMaterial, id, camera, width, height, dofRadianceName, depthStencil, radianceName, ldrColorName) {
            // https://catlikecoding.com/unity/tutorials/advanced-rendering/depth-of-field/

            this._cocParams.x = settings.depthOfField.focusDistance;
            this._cocParams.y = settings.depthOfField.focusRange;
            this._cocParams.z = settings.depthOfField.bokehRadius;
            this._cocParams.w = 0.0;
            this._cocTexSize.x = 1.0 / width;
            this._cocTexSize.y = 1.0 / height;
            this._cocTexSize.z = width;
            this._cocTexSize.w = height;
            var halfWidth = Math.max(Math.floor(width / 2), 1);
            var halfHeight = Math.max(Math.floor(height / 2), 1);
            var cocName = ldrColorName;
            var prefilterName = "DofPrefilter" + id;
            var bokehName = "DofBokeh" + id;
            var filterName = "DofFilter" + id;

            // CoC
            var cocPass = ppl.addRenderPass(width, height, 'cc-dof-coc');
            cocPass.addRenderTarget(cocName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            cocPass.addTexture(depthStencil, 'DepthTex');
            cocPass.setVec4('g_platform', this._configs.platform);
            cocPass.setMat4('proj', camera.matProj);
            cocPass.setVec4('cocParams', this._cocParams);
            cocPass.addQueue(QueueHint.OPAQUE).addCameraQuad(camera, dofMaterial, 0); // addCameraQuad will set camera related UBOs

            // Downsample and Prefilter
            var prefilterPass = ppl.addRenderPass(halfWidth, halfHeight, 'cc-dof-prefilter');
            prefilterPass.addRenderTarget(prefilterName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            prefilterPass.addTexture(dofRadianceName, 'colorTex');
            prefilterPass.addTexture(cocName, 'cocTex');
            prefilterPass.setVec4('g_platform', this._configs.platform);
            prefilterPass.setVec4('mainTexTexelSize', this._cocTexSize);
            prefilterPass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(dofMaterial, 1);

            // Bokeh blur
            var bokehPass = ppl.addRenderPass(halfWidth, halfHeight, 'cc-dof-bokeh');
            bokehPass.addRenderTarget(bokehName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            bokehPass.addTexture(prefilterName, 'prefilterTex');
            bokehPass.setVec4('g_platform', this._configs.platform);
            bokehPass.setVec4('mainTexTexelSize', this._cocTexSize);
            bokehPass.setVec4('cocParams', this._cocParams);
            bokehPass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(dofMaterial, 2);

            // Filtering
            var filterPass = ppl.addRenderPass(halfWidth, halfHeight, 'cc-dof-filter');
            filterPass.addRenderTarget(filterName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            filterPass.addTexture(bokehName, 'bokehTex');
            filterPass.setVec4('g_platform', this._configs.platform);
            filterPass.setVec4('mainTexTexelSize', this._cocTexSize);
            filterPass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(dofMaterial, 3);

            // Combine
            var combinePass = ppl.addRenderPass(width, height, 'cc-dof-combine');
            combinePass.addRenderTarget(radianceName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            combinePass.addTexture(dofRadianceName, 'colorTex');
            combinePass.addTexture(cocName, 'cocTex');
            combinePass.addTexture(filterName, 'filterTex');
            combinePass.setVec4('g_platform', this._configs.platform);
            combinePass.setVec4('cocParams', this._cocParams);
            combinePass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(dofMaterial, 4);
          };
          _proto2._addKawaseDualFilterBloomPasses = function _addKawaseDualFilterBloomPasses(ppl, settings, bloomMaterial, id, width, height, radianceName) {
            // Based on Kawase Dual Filter Blur. Saves bandwidth on mobile devices.
            // eslint-disable-next-line max-len
            // https://community.arm.com/cfs-file/__key/communityserver-blogs-components-weblogfiles/00-00-00-20-66/siggraph2015_2D00_mmg_2D00_marius_2D00_slides.pdf

            // Size: [prefilter(1/2), downsample(1/4), downsample(1/8), downsample(1/16), ...]
            var iterations = settings.bloom.iterations;
            var sizeCount = iterations + 1;
            this._bloomWidths.length = sizeCount;
            this._bloomHeights.length = sizeCount;
            this._bloomWidths[0] = Math.max(Math.floor(width / 2), 1);
            this._bloomHeights[0] = Math.max(Math.floor(height / 2), 1);
            for (var i = 1; i !== sizeCount; ++i) {
              this._bloomWidths[i] = Math.max(Math.floor(this._bloomWidths[i - 1] / 2), 1);
              this._bloomHeights[i] = Math.max(Math.floor(this._bloomHeights[i - 1] / 2), 1);
            }

            // Bloom texture names
            this._bloomTexNames.length = sizeCount;
            for (var _i2 = 0; _i2 !== sizeCount; ++_i2) {
              this._bloomTexNames[_i2] = "BloomTex" + id + "_" + _i2;
            }

            // Setup bloom parameters
            this._bloomParams.x = this._configs.useFloatOutput ? 1 : 0;
            this._bloomParams.x = 0; // unused
            this._bloomParams.z = settings.bloom.threshold;
            this._bloomParams.w = settings.bloom.enableAlphaMask ? 1 : 0;

            // Prefilter pass
            var prefilterPass = ppl.addRenderPass(this._bloomWidths[0], this._bloomHeights[0], 'cc-bloom-prefilter');
            prefilterPass.addRenderTarget(this._bloomTexNames[0], LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            prefilterPass.addTexture(radianceName, 'inputTexture');
            prefilterPass.setVec4('g_platform', this._configs.platform);
            prefilterPass.setVec4('bloomParams', this._bloomParams);
            prefilterPass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(bloomMaterial, 0);

            // Downsample passes
            for (var _i3 = 1; _i3 !== sizeCount; ++_i3) {
              var downPass = ppl.addRenderPass(this._bloomWidths[_i3], this._bloomHeights[_i3], 'cc-bloom-downsample');
              downPass.addRenderTarget(this._bloomTexNames[_i3], LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
              downPass.addTexture(this._bloomTexNames[_i3 - 1], 'bloomTexture');
              this._bloomTexSize.x = this._bloomWidths[_i3 - 1];
              this._bloomTexSize.y = this._bloomHeights[_i3 - 1];
              downPass.setVec4('g_platform', this._configs.platform);
              downPass.setVec4('bloomTexSize', this._bloomTexSize);
              downPass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(bloomMaterial, 1);
            }

            // Upsample passes
            for (var _i4 = iterations; _i4-- > 0;) {
              var upPass = ppl.addRenderPass(this._bloomWidths[_i4], this._bloomHeights[_i4], 'cc-bloom-upsample');
              upPass.addRenderTarget(this._bloomTexNames[_i4], LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
              upPass.addTexture(this._bloomTexNames[_i4 + 1], 'bloomTexture');
              this._bloomTexSize.x = this._bloomWidths[_i4 + 1];
              this._bloomTexSize.y = this._bloomHeights[_i4 + 1];
              upPass.setVec4('g_platform', this._configs.platform);
              upPass.setVec4('bloomTexSize', this._bloomTexSize);
              upPass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(bloomMaterial, 2);
            }

            // Combine pass
            var combinePass = ppl.addRenderPass(width, height, 'cc-bloom-combine');
            combinePass.addRenderTarget(radianceName, LoadOp.LOAD, StoreOp.STORE);
            combinePass.addTexture(this._bloomTexNames[0], 'bloomTexture');
            combinePass.setVec4('g_platform', this._configs.platform);
            combinePass.setVec4('bloomParams', this._bloomParams);
            combinePass.addQueue(QueueHint.BLEND).addFullscreenQuad(bloomMaterial, 3);
          };
          _proto2._addFsrPass = function _addFsrPass(ppl, settings, fsrMaterial, id, width, height, ldrColorName, nativeWidth, nativeHeight, colorName) {
            this._fsrTexSize.x = width;
            this._fsrTexSize.y = height;
            this._fsrTexSize.z = nativeWidth;
            this._fsrTexSize.w = nativeHeight;
            this._fsrParams.x = clamp(1.0 - settings.fsr.sharpness, 0.02, 0.98);
            var fsrColorName = "FsrColor" + id;
            var easuPass = ppl.addRenderPass(nativeWidth, nativeHeight, 'cc-fsr-easu');
            easuPass.addRenderTarget(fsrColorName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            easuPass.addTexture(ldrColorName, 'outputResultMap');
            easuPass.setVec4('g_platform', this._configs.platform);
            easuPass.setVec4('fsrTexSize', this._fsrTexSize);
            easuPass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(fsrMaterial, 0);
            var rcasPass = ppl.addRenderPass(nativeWidth, nativeHeight, 'cc-fsr-rcas');
            rcasPass.addRenderTarget(colorName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            rcasPass.addTexture(fsrColorName, 'outputResultMap');
            rcasPass.setVec4('g_platform', this._configs.platform);
            rcasPass.setVec4('fsrTexSize', this._fsrTexSize);
            rcasPass.setVec4('fsrParams', this._fsrParams);
            rcasPass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(fsrMaterial, 1);
            return rcasPass;
          };
          _proto2._addFxaaPass = function _addFxaaPass(ppl, fxaaMaterial, width, height, ldrColorName, colorName) {
            this._fxaaParams.x = width;
            this._fxaaParams.y = height;
            this._fxaaParams.z = 1 / width;
            this._fxaaParams.w = 1 / height;
            var pass = ppl.addRenderPass(width, height, 'cc-fxaa');
            pass.addRenderTarget(colorName, LoadOp.CLEAR, StoreOp.STORE, this._clearColorTransparentBlack);
            pass.addTexture(ldrColorName, 'sceneColorMap');
            pass.setVec4('g_platform', this._configs.platform);
            pass.setVec4('texSize', this._fxaaParams);
            pass.addQueue(QueueHint.OPAQUE).addFullscreenQuad(fxaaMaterial, 0);
            return pass;
          };
          _proto2._addUIQueue = function _addUIQueue(camera, pass) {
            var flags = SceneFlags.UI;
            if (this._cameraConfigs.enableProfiler) {
              flags |= SceneFlags.PROFILER;
              pass.showStatistics = true;
            }
            pass.addQueue(QueueHint.BLEND, 'default', 'default').addScene(camera, flags);
          }

          // ----------------------------------------------------------------
          // Forward
          // ----------------------------------------------------------------
          ;

          _proto2._addForwardRadiancePasses = function _addForwardRadiancePasses(ppl, id, camera, width, height, mainLight, colorName, depthStencilName, disableMSAA, depthStencilStoreOp) {
            if (disableMSAA === void 0) {
              disableMSAA = false;
            }
            if (depthStencilStoreOp === void 0) {
              depthStencilStoreOp = StoreOp.DISCARD;
            }
            // ----------------------------------------------------------------
            // Dynamic states
            // ----------------------------------------------------------------
            // Prepare camera clear color
            var clearColor = camera.clearColor; // Reduce C++/TS interop
            this._clearColor.x = clearColor.x;
            this._clearColor.y = clearColor.y;
            this._clearColor.z = clearColor.z;
            this._clearColor.w = clearColor.w;

            // Prepare camera viewport
            var viewport = camera.viewport; // Reduce C++/TS interop
            this._viewport.left = Math.round(viewport.x * width);
            this._viewport.top = Math.round(viewport.y * height);
            // Here we must use camera.viewport.width instead of camera.viewport.z, which
            // is undefined on native platform. The same as camera.viewport.height.
            this._viewport.width = Math.max(Math.round(viewport.width * width), 1);
            this._viewport.height = Math.max(Math.round(viewport.height * height), 1);

            // MSAA
            var enableMSAA = !disableMSAA && this._cameraConfigs.enableMSAA;
            assert(!enableMSAA || this._cameraConfigs.singleForwardRadiancePass);

            // ----------------------------------------------------------------
            // Forward Lighting (Main Directional Light)
            // ----------------------------------------------------------------
            var pass = this._cameraConfigs.singleForwardRadiancePass ? this._addForwardSingleRadiancePass(ppl, id, camera, enableMSAA, width, height, mainLight, colorName, depthStencilName, depthStencilStoreOp) : this._addForwardMultipleRadiancePasses(ppl, id, camera, width, height, mainLight, colorName, depthStencilName, depthStencilStoreOp);

            // Planar Shadow
            if (this._cameraConfigs.enableMainLightPlanarShadowMap) {
              this.addPlanarShadowQueue(camera, mainLight, pass);
            }

            // ----------------------------------------------------------------
            // Forward Lighting (Blend)
            // ----------------------------------------------------------------
            // Add transparent queue

            var sceneFlags = SceneFlags.BLEND | (camera.geometryRenderer ? SceneFlags.GEOMETRY : SceneFlags.NONE);
            pass.addQueue(QueueHint.BLEND).addScene(camera, sceneFlags, mainLight || undefined);
            return pass;
          };
          _proto2._addForwardSingleRadiancePass = function _addForwardSingleRadiancePass(ppl, id, camera, enableMSAA, width, height, mainLight, colorName, depthStencilName, depthStencilStoreOp) {
            assert(this._cameraConfigs.singleForwardRadiancePass);
            // ----------------------------------------------------------------
            // Forward Lighting (Main Directional Light)
            // ----------------------------------------------------------------
            var pass;
            if (enableMSAA) {
              var msaaRadianceName = "MsaaRadiance" + id;
              var msaaDepthStencilName = "MsaaDepthStencil" + id;
              var sampleCount = this._cameraConfigs.settings.msaa.sampleCount;
              var msPass = ppl.addMultisampleRenderPass(width, height, sampleCount, 0, 'default');
              msPass.name = 'MsaaForwardPass';

              // MSAA always discards depth stencil
              this._buildForwardMainLightPass(msPass, id, camera, msaaRadianceName, msaaDepthStencilName, StoreOp.DISCARD, mainLight);
              msPass.resolveRenderTarget(msaaRadianceName, colorName);
              pass = msPass;
            } else {
              pass = ppl.addRenderPass(width, height, 'default');
              pass.name = 'ForwardPass';
              this._buildForwardMainLightPass(pass, id, camera, colorName, depthStencilName, depthStencilStoreOp, mainLight);
            }
            assert(pass !== undefined);

            // Forward Lighting (Additive Lights)
            this.forwardLighting.addLightQueues(pass, camera, this._configs.mobileMaxSpotLightShadowMaps);
            return pass;
          };
          _proto2.addPlanarShadowQueue = function addPlanarShadowQueue(camera, mainLight, pass) {
            pass.addQueue(QueueHint.BLEND, 'planar-shadow').addScene(camera, SceneFlags.SHADOW_CASTER | SceneFlags.PLANAR_SHADOW | SceneFlags.BLEND, mainLight || undefined);
          };
          _proto2._addForwardMultipleRadiancePasses = function _addForwardMultipleRadiancePasses(ppl, id, camera, width, height, mainLight, colorName, depthStencilName, depthStencilStoreOp) {
            assert(!this._cameraConfigs.singleForwardRadiancePass);

            // Forward Lighting (Main Directional Light)
            var pass = ppl.addRenderPass(width, height, 'default');
            pass.name = 'ForwardPass';
            var firstStoreOp = this.forwardLighting.isMultipleLightPassesNeeded() ? StoreOp.STORE : depthStencilStoreOp;
            this._buildForwardMainLightPass(pass, id, camera, colorName, depthStencilName, firstStoreOp, mainLight);

            // Forward Lighting (Additive Lights)
            pass = this.forwardLighting.addLightPasses(colorName, depthStencilName, depthStencilStoreOp, id, width, height, camera, this._viewport, ppl, pass);
            return pass;
          };
          _proto2._buildReflectionProbePass = function _buildReflectionProbePass(pass, id, camera, colorName, depthStencilName, mainLight, scene) {
            if (scene === void 0) {
              scene = null;
            }
            // set viewport
            var colorStoreOp = this._cameraConfigs.enableMSAA ? StoreOp.DISCARD : StoreOp.STORE;

            // bind output render target
            if (forwardNeedClearColor(camera)) {
              this._reflectionProbeClearColor.x = camera.clearColor.x;
              this._reflectionProbeClearColor.y = camera.clearColor.y;
              this._reflectionProbeClearColor.z = camera.clearColor.z;
              var clearColor = rendering.packRGBE(this._reflectionProbeClearColor);
              this._clearColor.x = clearColor.x;
              this._clearColor.y = clearColor.y;
              this._clearColor.z = clearColor.z;
              this._clearColor.w = clearColor.w;
              pass.addRenderTarget(colorName, LoadOp.CLEAR, colorStoreOp, this._clearColor);
            } else {
              pass.addRenderTarget(colorName, LoadOp.LOAD, colorStoreOp);
            }

            // bind depth stencil buffer
            if (camera.clearFlag & ClearFlagBit.DEPTH_STENCIL) {
              pass.addDepthStencil(depthStencilName, LoadOp.CLEAR, StoreOp.DISCARD, camera.clearDepth, camera.clearStencil, camera.clearFlag & ClearFlagBit.DEPTH_STENCIL);
            } else {
              pass.addDepthStencil(depthStencilName, LoadOp.LOAD, StoreOp.DISCARD);
            }

            // Set shadow map if enabled
            if (this._cameraConfigs.enableMainLightShadowMap) {
              pass.addTexture("ShadowMap" + id, 'cc_shadowMap');
            }

            // TODO(zhouzhenglong): Separate OPAQUE and MASK queue

            // add opaque and mask queue
            pass.addQueue(QueueHint.NONE, 'reflect-map') // Currently we put OPAQUE and MASK into one queue, so QueueHint is NONE
            .addScene(camera, SceneFlags.OPAQUE | SceneFlags.MASK | SceneFlags.REFLECTION_PROBE, mainLight || undefined, scene ? scene : undefined);
          };
          _proto2._tryAddReflectionProbePasses = function _tryAddReflectionProbePasses(ppl, id, mainLight, scene) {
            var reflectionProbeManager = cclegacy.internal.reflectionProbeManager;
            if (!reflectionProbeManager) {
              return;
            }
            var probes = reflectionProbeManager.getProbes();
            var maxProbeCount = 4;
            var probeID = 0;
            for (var _iterator10 = _createForOfIteratorHelperLoose(probes), _step10; !(_step10 = _iterator10()).done;) {
              var probe = _step10.value;
              if (!probe.needRender) {
                continue;
              }
              var area = probe.renderArea();
              var width = Math.max(Math.floor(area.x), 1);
              var height = Math.max(Math.floor(area.y), 1);
              if (probe.probeType === renderer.scene.ProbeType.PLANAR) {
                if (!this._cameraConfigs.enablePlanarReflectionProbe) {
                  continue;
                }
                var window = probe.realtimePlanarTexture.window;
                var colorName = "PlanarProbeRT" + probeID;
                var depthStencilName = "PlanarProbeDS" + probeID;
                // ProbeResource
                ppl.addRenderWindow(colorName, this._cameraConfigs.radianceFormat, width, height, window);
                ppl.addDepthStencil(depthStencilName, gfx.Format.DEPTH_STENCIL, width, height, ResourceResidency.MEMORYLESS);

                // Rendering
                var probePass = ppl.addRenderPass(width, height, 'default');
                probePass.name = "PlanarReflectionProbe" + probeID;
                this._buildReflectionProbePass(probePass, id, probe.camera, colorName, depthStencilName, mainLight, scene);
              }
              ++probeID;
              if (probeID === maxProbeCount) {
                break;
              }
            }
          };
          _proto2._initMaterials = function _initMaterials(ppl) {
            if (this._initialized) {
              return 0;
            }
            setupPipelineConfigs(ppl, this._configs);

            // When add new effect asset, please add its uuid to the dependentAssets in cc.config.json.
            this._copyAndTonemapMaterial._uuid = "builtin-pipeline-tone-mapping-material";
            this._copyAndTonemapMaterial.initialize({
              effectName: 'pipeline/post-process/tone-mapping'
            });
            if (this._copyAndTonemapMaterial.effectAsset) {
              this._initialized = true;
            }
            return this._initialized ? 0 : 1;
          };
          return BuiltinPipelineBuilder;
        }();
        rendering.setCustomPipeline('Builtin', new BuiltinPipelineBuilder());
      } // if (rendering)
      cclegacy._RF.pop();
    }
  };
});

System.register("chunks:///_virtual/internal", ['./builtin-pipeline-settings.ts', './builtin-pipeline-types.ts', './builtin-pipeline.ts'], function () {
  return {
    setters: [null, null, null],
    execute: function () {}
  };
});

(function(r) {
  r('virtual:///prerequisite-imports/internal', 'chunks:///_virtual/internal'); 
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