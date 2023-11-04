# Get omni

This is the Cloudflare worker uploader for the https://get.omnicli.dev/ endpoint.

This allows to run the following to install [omni](https://omnicli.dev):

```sh
sh -c "$(curl -fsLS get.omnicli.dev)" -- clone git@github.com:<org>/<repo>
```
