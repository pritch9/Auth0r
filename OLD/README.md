# Auth0r
Welcome to Auth0r, the all-in-one user management module.


# NOTICE
Do not use this and expect security.  Fixes are being made to ensure a quality experience.  NOT YET FULLY TESTEST.  I am not responsible for any issues that arise from public usage.  This is not ready, I am fixing issues with deployment.  This is not complete and not meant to be used yet.

## Usage
There are a few hooks to allow you to customize the usage of Auth0r in your API.  Please let me know if I should release specific usage guides for different API types (REST, GrahpQL, etc.).

To initialize Auth0r, just create a new instance

`let Auth0r = new Auth0r(connection: any)`

To make things go quicker, you have to pass Knex connection options.  It just plugs them into the query builder.  I will make it easier in the future somehow.

### Middleware
Middleware is accessible by

`Auth0r.middleware()`

so in express, you would 'use' it like

```
let app = express();

...

app.use(Auth0r.middleware);

...
```

Note: in order for Auth0r to be effective, you have to 'use' Auth0r's middleware before anything else.  Express 'uses' sequentially, so if you notice you are sending invalid requests and the API is still returning something, then you probably have an ordering issue.
