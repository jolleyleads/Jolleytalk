# Jolley Talk setup

The deployed app uses the existing Render Python web service. Sign in as `jolley` with the password stored in Render as `JOLLEY_TALK_PASSWORD`.

## Browser calls

1. Keep `TWILIO_ACCOUNT_SID` and set `TWILIO_NUMBER` to an assigned voice-capable U.S. number in international format.
2. Create a US1 Standard API key in the same Twilio account. Save its SID and secret in Render as `TWILIO_VOICE_KEY_SID` and `TWILIO_VOICE_KEY_SECRET`. The legacy restricted key cannot sign Voice SDK access tokens.
3. Create a TwiML App in Twilio and set its Voice Request URL to `https://jolley-talk.onrender.com/voice/outbound` with the POST method. Save its SID in Render as `TWILIO_VOICE_APP_SID`.
4. Save and deploy the environment changes. Open Jolley Talk on HTTPS, enter a destination, and allow microphone access when placing a call.

The optional `ALLOWED_DESTINATIONS` variable restricts both voice and SMS to comma-separated numbers in international format. Remove this setting only if you intend to permit dialing other valid +1 numbers and your provider account supports those calls. Twilio trial restrictions still apply. The old `CALLBACK_NUMBER`, `TWILIO_API_KEY_SID`, and `TWILIO_API_KEY_SECRET` settings are unused by this version.

## Messages

Use an SMS-capable assigned number and configure provider messaging registration as applicable. Create a separate restricted key with Messages List and Create permissions and enter its values as `TWILIO_SMS_KEY_SID` and `TWILIO_SMS_KEY_SECRET`. The inbox reads recent messages from Twilio for the assigned number. No message webhook is required by this app.

Render's `/health` checks whether the server is running. Inbound voice, multiple accounts, number provisioning, and sponsored calling are outside the current build.
