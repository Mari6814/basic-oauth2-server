- Refactor `invalid_audience` entirely. The audience should be determined by the client and not be selection when creating the token. instead of letting the client request an audience, we will simply add all audiences recorded in the application to the JWT

- Still no refresh tokens
