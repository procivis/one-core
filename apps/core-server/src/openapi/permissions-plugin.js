(function() {
    window.RightPermissionPlugin = function() {
        return {
            wrapComponents: {
                OperationSummary: function(Orig, system) {
                    return function(props) {
                        try {
                            var opProps = props.operationProps;
                            var path = opProps && opProps.get ? opProps.get("path") : null;
                            var method = opProps && opProps.get ? opProps.get("method") : null;
                            method = method ? String(method).toLowerCase() : null;
                            var spec = system.specSelectors.specJson();
                            var op = (spec && path && method && spec.getIn) ?
                                spec.getIn(["paths", path, method]) :
                                null;
                            var permissions = op && op.get ? op.get("x-permissions") : null;
                            permissions = (permissions && permissions.toJS) ? permissions.toJS() : permissions;
                            var operationId = op && op.get ? op.get("operationId") : null;
                            var tags = op && op.get ? op.get("tags") : null;
                            tags = (tags && tags.toJS) ? tags.toJS() : tags;
                            var tag = tags[0];
                            var originalEl = system.React.createElement(Orig, props);

                            if (permissions && permissions.length && tag && operationId) {
                                requestAnimationFrame(function() {
                                    try {
                                        var targetBlock = document.querySelector('#operations-'+ tag +'-'+ operationId);
                                        if (!targetBlock) {
                                            return;
                                        }

                                        var btn = targetBlock.querySelector('button.opblock-summary-control');
                                        if (!btn) {
                                            return;
                                        }

                                        var wrapper = btn.querySelector('.opblock-summary-path-description-wrapper');
                                        if (!wrapper) {
                                            return;
                                        }

                                        if (btn.querySelector('.perm-badges')) {
                                            return;
                                        }

                                        var box = document.createElement('span');
                                        box.className = 'perm-badges';
                                        box.style.display = 'inline-flex';
                                        box.style.alignItems = 'center';
                                        box.style.gap = '6px';
                                        box.style.marginLeft = '12px';
                                        box.style.whiteSpace = 'nowrap';

                                        for (var j = 0; j < permissions.length; j++) {
                                            var s = document.createElement('span');
                                            s.textContent = permissions[j];
                                            s.style.fontSize = '11px';
                                            s.style.padding = '2px 8px';
                                            s.style.borderRadius = '12px';
                                            s.style.background = 'rgba(0,0,0,0.03)';
                                            s.style.border = '1px solid rgba(0,0,0,0.15)';
                                            s.style.fontWeight = '600';
                                            s.style.whiteSpace = 'nowrap';
                                            box.appendChild(s);
                                        }

                                        if (wrapper.nextSibling) {
                                            btn.insertBefore(box, wrapper.nextSibling);
                                        } else {
                                            btn.appendChild(box);
                                        }
                                    } catch (_e) {}
                                });
                            }

                            return originalEl;
                        } catch (err) {
                            return system.React.createElement(Orig, props);
                        }
                    };
                }
            }
        };
    };

    var orig = window.SwaggerUIBundle;
    if (typeof orig === "function" && !orig.__rightPermPatched) {
        var wrapped = function(opts) {
            opts = opts || {};
            opts.plugins = (opts.plugins || []).concat([window.RightPermissionPlugin]);
            return orig(opts);
        };

        for (var k in orig) {
            try {
                wrapped[k] = orig[k];
            } catch (e) {}
        }

        try {
            wrapped.presets = orig.presets;
        } catch (e) {}
        try {
            wrapped.plugins = orig.plugins;
        } catch (e) {}

        wrapped.__rightPermPatched = true;
        window.SwaggerUIBundle = wrapped;
    }
})();