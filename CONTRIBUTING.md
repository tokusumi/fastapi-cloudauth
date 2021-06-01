# Development Guideline

## Setup the development environment

At first, you need to clone "FastAPI-CloudAuth" repository.

Notice the working directory at the following descriptions is a root of cloned directory.

### Poetry

"FastAPI-CloudAuth" uses [Poetry](https://github.com/python-poetry/poetry) to create and activate virtual environment for developments (used also for build and publish to Pypi, else).

If "Poetry" is not available in your development environment, you can see at [official document](https://python-poetry.org/docs/) to install `poetry`.

You can confirm to install "Poetry" successfully as follows:

```
$ poetry --version
Poetry version 1.0.8
```

And now use `poetry` to create virtual environment and install the development dependencies:

```
$ poetry install
```

## Testing

You can use shortcut script for unit-test as follows:

```
$ poetry run bash scripts/test_local.sh -m unittest
```

But the most of "FastAPI-CloudAuth" testing is integration testing with cloud authentication services, which additional setup is required.

NOTE: Additional setup requires sensitive data like credential. we strongly recommend that make sure to restrict permissions and understand what our test code actually do.

Please create `load_env.sh` to help to load your environment variables for additional integration testing:

```
$ touch scripts/load_env.sh 
$ echo '#!/usr/bin/bash' > scripts/load_env.sh
```

### AWS Cognito

the following values are required:

* Region: Region code. ex) `us-east-1`, `ap-northeast-1`, ...
* Pool Id: Unique ID of your AWS Cognito User pool. ex) `region_9digit-hash`
* App client id: Unique ID of App client to access your user pool. ex) `26digit-hash`
* Access key ID: Required to programmatic calls to AWS from the AWS SDK, AWS CLI, etc. ex) `20digit-hash`
* Secret access key: Use it with Access key ID. ex) `40digit-hash`

above values are used to:

* Create test user tempolarily in AWS Cognito user pool.
* Get access/id token of created test user by AWS Cognito.
* Delete test user after testing.

#### AWS Access Key

Notice that "FastAPI-CloudAuth" uses AWS SDK for Python3 ("[boto3](https://aws.amazon.com/sdk-for-python/)") for managements of test user. This requires AWS Access Key.

Please read [How do I an create AWS Access key](https://aws.amazon.com/premiumsupport/knowledge-center/create-access-key/) and acquire valid "Access key ID" and "Secret access key".

#### Create your user pool

Go to [AWS Cognito](https://console.aws.amazon.com/cognito/users/).

Button "Create a user pool", and setup with:

* Required attributes: none
* Username attributes: email
* Email Delivery through Amazon SES: No
* App clients: create new one for testing. when you create it, :
    * Turn off "Generate client secret".
    * Turn on "ALLOW_ADMIN_USER_PASSWORD_AUTH" in "Auth Flows Configuration".
* and others are default

Then, if your user pool is created successfully, it shows "Pool Id".

Click "App clients" in General settings on the left side, it shows "App client id".

#### Testing for AWS Cognito

Add these values in `load_env.sh` as follows (replace \<str\> with your value acquired above):

```
export COGNITO_REGION=<Region>
export COGNITO_USERPOOLID=<Pool Id>
export COGNITO_APP_CLIENT_ID=<App client id>
export AWS_ACCESS_KEY_ID=<Access key ID>
export AWS_SECRET_ACCESS_KEY=<Secret access key>
```

Finally, you can run testing for only "AWS Cognito" as follows:

```
$ poetry run bash scripts/test_local.sh -m cognito
```

### Auth0

the following values are required:

* Domain: domain of `Default App`
* Client ID: client id of `Default App`
* Client Secret: client secret of `Default App`
* Management Client ID: client ID of custom application authorized with management API
* Management Client Secret: client secret of custom application authorized with management API
* Identifier: The identifier (audience) of any custom dummy API

above values are used to:

* Create test user tempolarily in Auth0.
* Get id token of created test user by Auth0.
* Delete test user after testing.

#### Setup Auth0

At first, you need to sign-up/log-in [Auth0](https://auth0.com/)

Button user icon at the top of right side, and type "Username-Password-Authentication" into `Tenant Settings`>`General`>`API Authorization Settings`>`Default Directory` and save it.

Next, goes to `Default App` settings from Applications at side bar, click "Show Advanced Settings" and turn on `Grant Types`>`password` and saved changes. It shows "Domain", "Client ID" and "Client Secret" there.

Next, create new application from application page at side bar with:

* Enter any name (noted as "Management APP" here)
* Choose `Machine to Machine Applications` as application's type
* Select "Auth0 Management API" as authorized API with "read:users", "update:users", "delete:users", "create:users" scopes

Created application settings page shows "Client ID" and "Client Secret", they are used as "Management Client ID" and "Management Client Secret".

At last, goes to APIs at side bar to create new API with:

* Enter any name (ex: "Dummy API")
* Type any identifier, URL is recommended (ex: "https://dummy-api/")

After successfully created, it shows "Identifier" at the just bottom of API name (same as identifier you typed).

And changes/add as follows:

* In `Settings`>`RBAC Settings`, turn on `Enable RBAC` and `Add Permissions in the Access Token` and save it.
* In `Permissions`, add new scope "read:test" and "write:test" (add something in descrition).

#### Testing for Auth0

Add these values in `load_env.sh` as follows (replace \<str\> with your value acquired above):

```
export AUTH0_DOMAIN=<Domain>
export AUTH0_CLIENTID=<Client ID>
export AUTH0_CLIENT_SECRET=<Client Secret>
export AUTH0_MGMT_CLIENTID=<Management Client ID>
export AUTH0_MGMT_CLIENT_SECRET=<Management Client Secret>
export AUTH0_AUDIENCE=<Identifier>
```

Then, you can run testing for only "Auth0" as follows:

```
$ poetry run bash scripts/test_local.sh -m auth0
```

### Firebase

the following values are required:

* Firebase project ID: the unique identifier for your Firebase project, which can be found in the URL of that project's console.
* Web API key: Required for login your Firebase Authentication service with http request (for getting id token). ex) `39digit-hash`
* base64 encoding credential: Required for Firebase Admin SDK. ex) `base64-encoding-large-string`

above values are used to:

* Create test user tempolarily in Firebase Authentication.
* Get id token of created test user by Firebase Authentication.
* Delete test user after testing.

#### Create your project

Go to [Firebase](https://console.firebase.google.com/) and create new project.

Then you can go to manage "Authentication" (from side bar).

Button "Sign-in method" tab, and make mail/password provider able. (Notice that our testing create test user by admin permission and doesn't send verification email.)

Then, go to "General" tab in project settings page and "Web API key" is listed.

Notice that "FastAPI-CloudAuth" uses Firebase Admin SDK for Python3 ("[Firebase Admin Python SDK](https://firebase.google.com/docs/reference/admin/python)") for managements of test user. This requires "Google services account".

Click "Service accounts" tab in project settings, and "Generate new private key" for Firebase Admin SDK, then downloading json file starts.

Make sure to download credential json file (here noted filename as `service-cred.json`) and base64 encoding it as following command:

```
$ cat service-cred.json | base64 -w 0 > base64-credential
```

The string in `base64-credential` is "base64 encoding credential"

#### Testing for Firebase Authentication

Add these values in `load_env.sh` as follows (replace \<str\> with your value acquired above):

```
export FIREBASE_PROJECTID=<Firebase Project ID>
export FIREBASE_APIKEY=<Web API key>
export FIREBASE_BASE64_CREDENCIALS=<base64 encoding credential>
```

Then, you can run testing for only "Firebase Authentication" as follows:

```
$ poetry run bash scripts/test_local.sh -m firebase
```

### Tesing all at once

Here you can run all testing at one line as follows:

```
$ poetry run bash scripts/test_local.sh
```

## GitHub Actions

If you follow above setup, you would be able to run GitHub Action in your fork repository.

At first, fork "FastAPI-CloueAuth". add all values into GitHub Secrets with same key-value pairs.

When you commit at your forked "master" branch or pull request into "master" branch, workflows runs. 
