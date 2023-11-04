const shellScriptContent: string = 'SHELL_SCRIPT_CONTENT';

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (new URL(request.url).pathname === "/") {
			return new Response(shellScriptContent, {
				headers: {
					'Content-Type': 'text/plain',
					'Content-Disposition': 'attachment; filename="getomni.sh"',
				},
			})
		} else {
			return new Response("Not found", { status: 404 })
		}
	},
};
