<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\LoginUserRequest;
use App\Mail\EmailVerify;
use App\Models\User;
use App\Traits\HttpResponses;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    use HttpResponses;

    public function login(LoginUserRequest $request){
        
        // validation requested data
        $request->validated($request->all());
        
        if(!Auth::attempt($request->only(['email','password']))) // if creadantial does not matched
        {
            return $this->error('', 'Credentials do not match', 401);
        }

        $user = Auth::user(); // store user information

        if(is_null($user->email_verified_at)) // if email is not verified
        {
            $user = User::find($user->id);
            $user->otp = rand(1000, 9999);
            $user->save();

            // send otp to user email
            Mail::to($user->email)->send(new EmailVerify([
                'user'  =>  $user
            ]));

            // clearing auth session
            Auth::logout();

            return $this->success([], 'We send an otp to your email address. Please verify your email first');
        }

        return $this->success([
            'user' => $user,
            'token' => $user->createToken('Api Token of'. $user->name)->plainTextToken
        ], "Credentials matched successfully");
         
    }

    public function register(StoreUserRequest $request){

        $request->validated($request ->all());
        $msg = "OTP Send Successfully";

        try{
            $otp = rand(1000, 9999);

            $user = User::create([
                'name'=> $request->first_name . ' ' . $request->last_name,
                'email'=>$request->email,
                'phone'=>$request->phone,
                'otp'=>$otp,
                'password'=> bcrypt($request->password),
            ]);

            Mail::to($user->email)->send(new EmailVerify([
                'user'  =>  $user
            ]));
        }
        catch(\Exception $e)
        {
            $msg = $e->getMessage();
        }
        

        return $this->success([
            'user' => $user,
            // 'token' => $user->createToken('API Token of'. $user->name)->plainTextToken
        ], $msg);


    }


    /** check user provided OTP */
    public function checkOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' =>  'required|email|exists:users',
            'otp' =>  'required',
        ]);

        if($validator->fails())
        {
            return $this->error([], $validator->errors()->first());
        }
        
        $user = User::where('email', $request->email)->where('otp', $request->otp);

        if($user->exists())
        {
            $msg = "Otp Matched Successfully";
            $user = $user->first();

            $user->update([
                'email_verified_at'   => now(),
                'otp'   =>  null
            ]);

            return $this->success([
                'user' => $user,
                'token' => $user->createToken('API Token of'. $user->name)->plainTextToken
            ], $msg);
        }
        else
        {
            $msg = "Otp Not Matched";
            return $this->success([], $msg);
        }
    }

    public function logout(){

        Auth::user()->currentAccessToken()->delete();

        return $this->success([],'You have successfully logged out and your token has been deleted.');
    }

    public function profile(Request $request){
        
        $user = $request->user();
        
        return $this->success([
            'user' => $user
        ]);
    }
}
