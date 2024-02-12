<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Validator;
use App\Models\OTP;
use Illuminate\Support\Facades\Mail;
use App\Mail\OTPmail;
use Illuminate\Support\Facades\Hash;
class AuthController extends Controller
{

    public function limit($email)
    {
        User::get()->where('email',$email)->count();
    }

    public function login(Request $request)
    {
        $validate = Validator::make($request->all(),[
            'email'=>'required|string',
            'password'=>'required|string',
        ]);

        if($validate->fails())
        {
            throw ValidationException::withMessages([
                'Inputs' => ['Please check your inserted details.'],
            ]);
        }



        $credentials = $request->only('email', 'password');

        if (Auth::attempt($credentials)) {
            $user = User::where('email', $request->email)->firstOrFail();
            $token = $user->createToken('auth-token')->plainTextToken;

            return response()->json(['token' => $token]);
        }

        throw ValidationException::withMessages([
            'email' => ['The provided credentials are incorrect.'],
        ]);
    }

    public function profile(Request $request)
    {
        return response()->json([
            'status'=>200,
            'data'=>Auth::user()
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();
        return response()->json(['message' => 'Successfully logged out']);
    }

    public function register(Request $req)
    {
        $validate = Validator::make($req->all(),[
            'name'=>'string|max:255|required|',
            'email'=>'string|required|max:50',
            'password'=>'string|required|min:8|max:20|confirmed',
            'password_confirmation'=>'string|required|min:8|max:20'
        ]);

        if($validate->fails())
        {
            return response()->json(
                [
                    'status'=>402,
                    'data'=>'please check your inserted datas'
                ],402
            );
        }else{

            if($this->limit($req->email) > 0)
            {
                return response()->json(
                    [
                        'status'=>401,
                        'message'=>'Email already used'
                    ],401
                );

            }else{
                $validToken = rand(10,100..'00');
                OTP::create(['email'=>$req->email,'token'=>$validToken]);
                Mail::to($req->email)->send(new OTPmail($validToken));
                setcookie("email",$req->email,time()+3600);
                setcookie("name",$req->name,time()+3600);
                setcookie("password",$req->password,time()+3600);

                return response()->json(
                    [
                        'status'=>200,
                        'message'=>'Please check your email for OTP',
                    ],200
                );
            }
        }



    }

    public function verify(Request $req)
    {
        $validate = Validator::make($req->all(),[
            'name'=>'string|max:255|required|',
            'email'=>'string|required|max:50',
            'password'=>'string|required|min:8|max:20|',
            'token'=>'string|min:4|max:6'
        ]);

        if($validate->fails())
        {
            return response()->json(
                [
                    'status'=>402,
                    'messaage'=>'please check your inputs'
                ],402
            );
        }
        else
        {
            $otp = OTP::where('token', $req->token)
                ->where('email', $req->email)
                ->where('is_verified', false)
                ->first();
            if($otp)
            {
                $otp->is_verified = true;
                $otp->save();
                User::create(['email'=>$req->email,'name'=>$req->name,'password'=>Hash::make($req->password)]);
                return response()->json([
                    'status'=>200,
                    'message'=>'User created'
                ],200);
            }else{
                return response()->json([
                    'status'=>401,
                    'messaged'=>'WRONG OTP'
                ],401);
            }
        }
    }

    public function checkAuth(Request $request)
    {
        $user = Auth::check();
        if($user)
        {
            return response()->json([
                'status'=>200
            ],200);
        }else
        {
            return response()->json([
                'status'=>401
            ],401);
        }
    }
}
