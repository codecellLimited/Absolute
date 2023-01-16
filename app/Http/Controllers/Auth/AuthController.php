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

class AuthController extends Controller
{
    use HttpResponses;

    public function login(LoginUserRequest $request){
        $request->validated($request->all());

        
        if(!Auth::attempt($request->only(['email','password']))){
            return $this->error('', 'Credentials do not match', 401);
        }

        $user = User::where('email', $request->email)->first();

        return $this->success([
            'user' => $user,
            'token' => $user->createToken('Api Token of'. $user->name)->plainTextToken
        ]);
         
    }

    public function register(StoreUserRequest $request){

        $request->validated($request ->all());
        $msg = "OTP Send Successfully";

        try{
            $otp = rand(100000, 999999);

            $user = User::create([
                'name'=> $request->name,
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
                'token' => $user->createToken('API Token of'. $user->name)->plainTextToken
            ], $msg);


    }

    public function logout(){

        Auth::user()->currentAccessToken()->delete();

        return $this->success([],'You have successfully logged out and your token has been deleted.');
    }
}
