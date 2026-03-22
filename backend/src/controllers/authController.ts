import { validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/User';
import { Request, Response } from 'express';
import { OAuth2Client } from 'google-auth-library';
// Augment express-serve-static-core
declare module 'express-serve-static-core' {
    interface Request {
        user?: IUser;
    }
}

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Generate JWT Token
const generateToken = (id: string): string => {
    const jwtSecret = process.env.JWT_SECRET;
    const jwtExpire = process.env.JWT_EXPIRE || '7d';

    if (!jwtSecret) {
        throw new Error('JWT_SECRET is not defined');
    }

    return jwt.sign({ id }, jwtSecret, {
        expiresIn: jwtExpire as any
    });
};

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
export const register = async (req: Request, res: Response): Promise<void> => {
    try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            res.status(400).json({
                success: false,
                errors: errors.array()
            });
            return;
        }

        const { name, email, password, role } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(400).json({
                success: false,
                message: 'User already exists with this email'
            });
            return;
        }

        // Create user
        const user = await User.create({
            name,
            email,
            password,
            role
        });

        // Generate token
        const token = generateToken(user._id.toString());

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during registration'
        });
    }
};


export const login = async (req: Request, res: Response): Promise<void> => {
    try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            res.status(400).json({
                success: false,
                errors: errors.array()
            });
            return;
        }

        const { email, password } = req.body;

        // Check if user exists (include password field)
        const user = await User.findOne({ email }).select('+password');
        if (!user) {
            res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
            return;
        }

        // Check if password matches
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
            return;
        }

        // Generate token
        const token = generateToken(user._id.toString());

        res.status(200).json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
};


export const getMe = async (req: Request, res: Response): Promise<void> => {
    try {
        if (!req.user) {
            res.status(401).json({
                success: false,
                message: 'Not authorized'
            });
            return;
        }

        res.status(200).json({
            success: true,
            user: {
                id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                role: req.user.role
            }
        });
    } catch (error) {
        console.error('GetMe error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};


export const updateDetails = async (req: Request, res: Response): Promise<void> => {
    try {
        if (!req.user) {
            res.status(401).json({
                success: false,
                message: 'Not authorized'
            });
            return;
        }

        const { name, email } = req.body;

        // If email is changing, check for duplicates
        if (email && email !== req.user.email) {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                res.status(400).json({
                    success: false,
                    message: 'Email is already in use'
                });
                return;
            }
        }

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { name, email },
            { new: true, runValidators: true }
        );

        if (!user) {
            res.status(404).json({
                success: false,
                message: 'User not found'
            });
            return;
        }

        res.status(200).json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('UpdateDetails error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during update'
        });
    }
};


export const googleLogin = async (req: Request, res: Response): Promise<void> => {
    try {
        const { token, role } = req.body;

        if (!token) {
            res.status(400).json({ success: false, message: 'Google credential token is required' });
            return;
        }

        let ticket;
 
        try {
            ticket = await client.verifyIdToken({
                idToken: token,
                audience: process.env.GOOGLE_CLIENT_ID
            });
        } catch (verificationError) {
            console.error('Google token verification failed:', verificationError);
            res.status(401).json({ success: false, message: 'Invalid or expired Google token' });
            return;
        }

        const payload = ticket.getPayload();
        if (!payload || !payload.email) {
            res.status(400).json({ success: false, message: 'Google token missing required profile information' });
            return;
        }

        const { email, name, sub: googleId, picture } = payload;

        // Check if user exists
        let user = await User.findOne({ email });

        if (!user) {
            // FIX 4: Strict Enum checking for roles. 
            // This prevents someone from sending {"role": "Admin"} in Postman and bypassing your security.
            const validRoles = ['Teacher', 'Student'];
            const assignedRole = validRoles.includes(role) ? role : 'Student';

            // Register new user
            user = await User.create({
                name: name || 'Google User', // FIX 5: Fallback. Google users don't always have a name set.
                email: email.toLowerCase(),  // FIX 6: Normalize email casing to match your Mongoose schema
                googleId,
                role: assignedRole,
                avatar: picture || ''
            });
        } else {
            // If user exists, link Google ID and update avatar if missing
            // SECURITY NOTE: Notice we do NOT update the role here. 
            // This prevents a Student from re-authenticating and changing their role to Teacher.
            let requiresSave = false;
            
            if (!user.googleId) {
                user.googleId = googleId;
                requiresSave = true;
            }
            if (picture && !user.avatar) {
                user.avatar = picture;
                requiresSave = true;
            }
            
            if (requiresSave) {
                await user.save();
            }
        }

        // Generate application token
        const appToken = generateToken(user._id.toString());

        res.status(200).json({
            success: true,
            token: appToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                avatar: user.avatar
            }
        });

    } catch (error) {
        // FIX 7: This catch block is now reserved ONLY for true server/database failures.
        console.error('Unexpected Server Error during Google login:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during Google login'
        });
    }
};


// @desc    Get top users by points
// @route   GET /api/auth/leaderboard
// @access  Public
export const getLeaderboard = async (req: Request, res: Response): Promise<void> => {
    try {
        const users = await User.find({ role: 'Student' })
            .select('name points')
            .sort({ points: -1 })
            .limit(10);

        res.status(200).json({
            success: true,
            data: users
        });
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error fetching leaderboard'
        });
    }
};
