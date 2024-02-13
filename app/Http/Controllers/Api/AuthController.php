<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Validator;
use App\Models\OTP;
use Illuminate\Support\Facades\Mail;
use App\Mail\OTPmail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use App\Mail\resetMail;
use Illuminate\Support\Facades\DB;
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
            $user = Auth::user();
            $token = $user->createToken('auth-token');
            $token->accessToken->expires_at = now()->addHour();




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
                    'data'=>'please check your inserted datas',
                    'datas'=>$validate->messages()
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
                    'message'=>'please check your inputs',
                    'data'=>$validate->messages()
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

    public function reset(Request $req)
    {
        $validate = Validator::make($req->all(),[
            'email'=>'required|string|'
        ]);



        if($validate->fails())
        {
            return response()->json(
                [
                    'status'=>422,
                    'message'=>'Please check your inputs'
                ],422
            );
        }

        $url = 'http://127.0.0.1:5500/verifyReset.html?token=';
        $token = Str::random(64);

        DB::table('password_reset_tokens')->insert(
            [
                'email'=>$req->email,
                'token'=>$token,
                'created_at'=>Carbon::now()
            ]
        );





        Mail::to($req->email)->send(new resetMail($url.$token));

        return response()->json([
            'status'=>200,
            'message'=>'Please check your email for the link'
        ],200);
    }

    public function resetpassword(Request $request)
    {
        $validate = Validator::make($request->all(),[
            'token'=>'string|required',
            'password'=>'string|required|min:8|max:20|confirmed',
            'password_confirmation'=>'string|required|min:8|max:20'
        ]);

        if($validate->fails()){
            response()->json([
                'status'=>422,
                'message'=>'Check your inputs'
            ],422);
        }

        $passwordResetToken = DB::table('password_reset_tokens')
            ->where('token', $request->token)
            ->where('used', false)
            ->first();

        if($passwordResetToken)
        {
            DB::table('password_reset_tokens')
                ->where('token', $request->token)
                ->update(['used' => true]);

            $user = User::where('email',$passwordResetToken->email)->first();
            $user->password = Hash::make($request->password);
            $user->save();

            return response()->json(
                [
                    'status'=>200,
                    'message'=>'Password has been changed'
                ],200
            );
        }
        return response()->json([
            'status'=>401,
            'message'=>'INVALID TOKEN',
        ],401);
    }
}
