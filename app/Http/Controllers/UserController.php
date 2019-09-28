<?php

namespace App\Http\Controllers;

use Illuminate\Routing\Controller as BaseController;
use App\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;

use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Facades\JWTFactory;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\PayloadFactory;
use Tymon\JWTAuth\JWTManager as JWT;


class UserController extends BaseController
{
    public function register(Request $request) 
    {
    	try {
    		$validator = Validator::make($request->json()->all(), [
    			'name' => 'required|string|max:255',
    			'email' => 'required|string|email|max:255|unique:users',
    			'password' => 'required|string|min:6',
    		]);

    		if($validator->fails()) {
    			return response()->json($validator->error()->toJson(), 400);
    		} //End if


    		$user = User::create([
    			'name' => $request->json()->get('name'),
    			'email' => $request->json()->get('email'),
    			'password' => Hash::make($request->json()->get('password')),
    		]);


    		$token = JWTAuth::fromUser($user);

    		return response()->json(compact('user', 'token'));
    	} catch (Exception $e) {
    		log::error(json_encode($e));
    	}
    }


  public function login(Request $request)
  {
	$credentials = $request->json()->all();
	try {
	    $token = JWTAuth::attempt($credentials);
	    // print_r($token);
	    // if(!$token == JWTAuth::attempt($credentials)) {
	    // 	return response()->json(['error'=> 'invalid_credentials'], 400);
	    // } //End if
	} catch (Exception $e) {
	    return response()->json(['error' => 'cloud_not_create_token'], 500);
	} //End Try-catch

	return response()->json(compact('token'));
  }

    public function getAuthenticatedUser()
    {
        try {
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user_not_found'], 404);
            }
        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['token_expired'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['token_invalid'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['token_absent'], $e->getStatusCode());
        }
        return response()->json(compact('user'));
    }
}
