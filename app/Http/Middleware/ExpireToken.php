<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;

class ExpireToken
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if(Auth::user() && Auth::user()->tokens()->where('last_used_at', '<=', Carbon::now()->subHours(1))->delete())
        {
            Auth::user()->tokens()->delete();
            Auth::logout();

            return response()->json(
                [
                    'status'=>401,
                    'Messaged'=>'Token Expired'
                ],401
            );
        }




        return $next($request);
    }
}
