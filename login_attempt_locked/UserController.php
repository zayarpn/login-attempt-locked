<?php

namespace App\Http\Controllers;

use App\services\LoginAttempts;
use App\User;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class UserController extends Controller
{
    // set login attempts limitations
    private $maxAttempts    = 3; // Limit 3 times
    private $decayMinutes   = 1440; // 60 mins * 24

    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['userLogin']]);
    }

    public function userLogin()
    {

        $req_data = request(['email', 'password']);
        $tmp_arr = array_merge($req_data, array('record_status' => '1'));
        $credentials = array_merge($tmp_arr, array('role_id' => '2'));
        $credentials = array_merge($credentials, array('email_verified' => '1'));

        $user_info = User::where('email', $credentials['email'])
            ->where('role_id', '2')
            ->where('record_status', '1')
            ->where('email_verified', '1')
            ->first();

        if (!$token = JWTAuth::attempt($credentials)) {
            $response_msg = 'Invalid credential.';
            if (!is_null($user_info) && $user_info->email_verified == 1 && !empty(request('form'))) {
                // validate hasTooManyLoginAttempts
                $has_login_attempts_max = LoginAttempts::hasTooManyLoginAttempts($user_info, $this->maxAttempts, $this->decayMinutes);
                $response_msg = $has_login_attempts_max ? 'This account is locked for a while cause of max login attempt with invalid credentials.' : $response_msg;
            }
            return response([
                'status' => 'error',
                'error' => 'invalid.credentials',
                'msg' => $response_msg
            ], 401);
        }

        $is_still_locked = LoginAttempts::stillLocked($user_info['id'] . $user_info['email'] . $user_info['role_id']);
        if ($is_still_locked) {
            return response([
                'status' => 'error',
                'error' => 'invalid.credentials',
                'msg' => 'Acoount is still locked'
            ], 403);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth('api')->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth('api')->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'user' => $this->guard()->user(),
            'token_type' => 'bearer',
            'expires_in' => 60
        ]);
    }

    public function guard()
    {
        return \Auth::Guard('api');
    }
}
