export const manifest = (() => {
function __memo(fn) {
	let value;
	return () => value ??= (value = fn());
}

return {
	appDir: "_app",
	appPath: "_app",
	assets: new Set([]),
	mimeTypes: {},
	_: {
		client: {start:"_app/immutable/entry/start.BzM0ciju.js",app:"_app/immutable/entry/app.Ctp6OlHn.js",imports:["_app/immutable/entry/start.BzM0ciju.js","_app/immutable/chunks/DEy2NrEg.js","_app/immutable/chunks/_AI6n9a0.js","_app/immutable/chunks/TpfQPFTV.js","_app/immutable/entry/app.Ctp6OlHn.js","_app/immutable/chunks/_AI6n9a0.js","_app/immutable/chunks/DfDyS1yD.js","_app/immutable/chunks/BKh3Xi8y.js","_app/immutable/chunks/TpfQPFTV.js","_app/immutable/chunks/axEuc7fy.js","_app/immutable/chunks/D1pR2dl4.js"],stylesheets:[],fonts:[],uses_env_dynamic_public:false},
		nodes: [
			__memo(() => import('./nodes/0.js')),
			__memo(() => import('./nodes/1.js')),
			__memo(() => import('./nodes/2.js')),
			__memo(() => import('./nodes/3.js'))
		],
		remotes: {
			
		},
		routes: [
			{
				id: "/login",
				pattern: /^\/login\/?$/,
				params: [],
				page: { layouts: [0,], errors: [1,], leaf: 2 },
				endpoint: null
			},
			{
				id: "/register",
				pattern: /^\/register\/?$/,
				params: [],
				page: { layouts: [0,], errors: [1,], leaf: 3 },
				endpoint: null
			}
		],
		prerendered_routes: new Set([]),
		matchers: async () => {
			
			return {  };
		},
		server_assets: {}
	}
}
})();
