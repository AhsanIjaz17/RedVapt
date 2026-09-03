// src/config/passport.js
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import * as authService from '../services/auth.service.js';
import config from './env.js';

if (!config.GOOGLE_CLIENT_ID || config.GOOGLE_CLIENT_ID.includes('your-google')) {
    // Silenced OAuth warning as Google Sign-in is intentionally disabled
} else {
    passport.use(new GoogleStrategy({
        clientID: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        callbackURL: config.GOOGLE_REDIRECT_URI,
        scope: ['profile', 'email']
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const user = await authService.syncGoogleUser(profile);
            return done(null, user);
        } catch (err) {
            console.error('[Passport] Google Sync Error:', err);
            return done(err, null);
        }
    }));
}

// We use stateless JWT, but passport requires these for sessions if enabled
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, { id }));

export default passport;
