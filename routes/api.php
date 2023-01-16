<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;


Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});




//public Route

Route:: post('/login', [AuthController::class,'login']);
Route:: post('/register', [AuthController::class,'register']);
Route::post('check-otp', [AuthController::class, 'checkOtp']);

//protected Route

Route::group(['middleware' => ['auth:sanctum']], function (){
    Route:: resource('/tasks', TaskController::class);  
    Route:: post('/logout',[AuthController::class,'logout']);
});