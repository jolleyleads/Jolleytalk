# Jolley Talk setup

In the Render service's Environment tab, add the following variables.

| Variable | Value |
| --- | --- |
| `TWILIO_ACCOUNT_SID` | Twilio Account SID starting with AC |
| `TWILIO_API_KEY_SID` | Twilio API key SID starting with SK |
| `TWILIO_API_KEY_SECRET` | Twilio API key secret |
| `TWILIO_NUMBER` | Your voice-capable Twilio number |
| `CALLBACK_NUMBER` | Your phone number |
| `ALLOWED_DESTINATIONS` | Comma-separated destination phone numbers |
| `JOLLEY_TALK_PASSWORD` | A unique password of at least 16 characters |

Use international format for all phone numbers, such as `+12025550123`. On a Twilio trial, verify the callback and destination numbers in Twilio first. Store the actual values in Render's Environment tab.

Save and deploy, then open the app and sign in as `jolley` with the password you chose. Select a destination and press **Start callback**. Answer your phone to connect. The destination sees your Twilio number.

The `/health` endpoint verifies that the server is running. For outbound call issues, check the Twilio Voice logs.
