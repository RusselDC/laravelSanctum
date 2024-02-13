<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware(['auth:sanctum','tokenExpiration'])->get('user',[AuthController::class,'profile']);
Route::middleware(['auth:sanctum','tokenExpiration'])->get('logout',[AuthController::class,'logout']);
Route::middleware(['auth:sanctum','tokenExpiration'])->get('checkAuth',[AuthController::class,'checkAuth']);

Route::post('login',[AuthController::class,'login']);
Route::post('register',[AuthController::class,'register']);
Route::post('verify',[AuthController::class,'verify']);
Route::post('reset',[AuthController::class,'reset']);
Route::post('resetpassword',[AuthController::class,'resetpassword']);
