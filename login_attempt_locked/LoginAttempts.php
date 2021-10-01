<?php

namespace App\services;
use Illuminate\Support\Facades\Cache;
use App\Http\Controllers\API\V1\BaseController;

class LoginAttempts {
    /**
     * set limitation of login attempts
     * @author Zayar Phone Naing crafted @ 2020/12/17
     * @last_maintained @ 2020/12/21 Zayar Phone Naing
     * @param user, maxAttempts, decayMinutes
     * @return
     */
    public static function hasTooManyLoginAttempts($user, $maxAttempts, $decayMinutes)
    {
        if (!is_null($user)){
            // store email with its id & role_id
            $login_email = $user->id.$user->email.$user->role_id;
            if (Cache::has($login_email)) {
                $login_attempts = Cache::get($login_email);
                if($login_attempts < $maxAttempts){
                    $increase_login_attempts = Cache::increment($login_email);
                    if($increase_login_attempts == $maxAttempts){
                        Cache::put($login_email, $increase_login_attempts, now()->addMinutes($decayMinutes));
                        return true;
                    }
                }else {
                    return true;
                }
            }else {
                // set temporary remember time(sec) for locked
                Cache::add($login_email, 1, 3600);
            }
        }
        return false;
    }

    /**
     * check still cache locked
     * @author Zayar Phone Naing crafted @ 2020/12/17
     * @last_maintained @ 2020/12/21 Zayar Phone Naing
     * @param email
     * @return
     */
    public static function stillLocked($email)
    {
        if (Cache::has($email)) {
            if(Cache::get($email) >= 3){
                return true;
            }
            Cache::pull($email);
        }
        return false;
    }

    /**
     * clear(cache) login locked
     * @author Zayar Phone Naing crafted @ 2021/01/20
     * @last_maintained @ 2021/01/20 Zayar Phone Naing
     * @param email
     * @return
     */
    public static function clearLoginLocked($email)
    {
        if (Cache::has($email)) {
            Cache::forget($email);
            return true;
        }
        return false;
    }
   
}