import { LoginResponse, UserResponse } from '@sharedTypes/MessageTypes';
import { TokenContent, User, UserWithLevel } from '@sharedTypes/DBTypes';
import { NextFunction, Request, Response } from 'express';
import CustomError from '../../classes/CustomError';
import fetchData from '../../utils/fetchData';
import OTPAuth from 'otpauth';
import twoFAModel from '../models/twoFAModel';
import QRCode from 'qrcode';
import jwt from 'jsonwebtoken';
// TODO: Import necessary types and models

// TODO: Define setupTwoFA function
const setupTwoFA = async (
  req: Request<{}, {}, User>,
  res: Response<{qrCodeUrl: string}>,
  next: NextFunction
) => {
  try {
    // TODO: Register user to AUTH API
    const options: RequestInit= {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const userResponse = await fetchData<UserResponse>(
      process.env.AUTH_URL + '/api/v1/users',
      options
    );
    console.log('userResponse', userResponse);

    res.json({qrCodeUrl: 'qrCodeUrl'});

    // TODO: Generate a new 2FA secret
    const secret = new OTPAuth.Secret();

    // TODO: Create the TOTP instance
    const totp = new OTPAuth.TOTP({
      issuer: 'MFA Starter',
      label: userResponse.user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret:  secret
    });

    // TODO: Store or update the 2FA data in the database
    await twoFAModel.create({
      email: userResponse.user.email,
      userId: userResponse.user.user_id,
      twoFactorEnabled: true,
      twoFactorSecret: secret.base32
    })

    // TODO: Generate a QR code and send it in the response
    const imageUrl = await QRCode.toDataURL(totp.toString());

    res.json({qrCodeUrl: imageUrl});

  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// TODO: Define verifyTwoFA function
const verifyTwoFA = async (
  req: Request<{}, {}, {email: string, code: string}>,
  res: Response<LoginResponse>,
  next: NextFunction
) => {
  const {email, code} = req.body;

  try {
    // TODO: Retrieve 2FA data from the database
    const twoFactorData = await twoFAModel.findOne({email});
    if (!twoFactorData || !twoFactorData.twoFactorEnabled) {
      next(new CustomError('2FA data not found', 400));
      return;
    }
    console.log('twoFactorData', twoFactorData);

    // TODO: Validate the 2FA code
    const totp = new OTPAuth.TOTP({
      issuer: 'MFA Starter',
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(twoFactorData.twoFactorSecret)
    });

    const isValid = totp.validate({
      token: code,
      window: 1});

    // TODO: If valid, get the user from AUTH API
    if (!isValid) {
      next(new CustomError('Invalid code', 400));
      return;
    }

    // TODO: Create and return a JWT token
    const UserResponse = await fetchData<UserWithLevel>(
      process.env.AUTH_URL + '/api/v1/users/' + twoFactorData.userId
    );

    if (!UserResponse) {
      next(new CustomError('User not found', 401));
      return;
    }

    const tokenContent:TokenContent = {
      user_id: UserResponse.user_id,
      level_name: UserResponse.level_name,
    }
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET not found');
    }

    const token = jwt.sign(tokenContent, process.env.JWT_SECRET)
    const LoginResponse:LoginResponse = {
      user: UserResponse,
      token,
      message: 'Login successful'
    }

    res.json(LoginResponse);

  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {setupTwoFA, verifyTwoFA};
