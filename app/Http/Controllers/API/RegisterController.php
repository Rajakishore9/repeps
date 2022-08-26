<?php

namespace App\Http\Controllers\API;
 
use Illuminate\Http\Request;
 
use App\Models\User;

use App\Http\Controllers\API\BaseController as BaseController;

use Illuminate\Support\Facades\Auth;

use Validator;
use Illuminate\Support\Facades\Hash;

class RegisterController extends BaseController
{
    /**
     * Registration Req
     */
    public function register(Request $request)
    {
        // $this->validate($request, [
        //     'name' => 'required|min:4',
        //     'email' => 'required|email',
        //     'password' => 'required|min:8',
        // ]);
  
        // $user = User::create([
        //     'name' => $request->name,
        //     'email' => $request->email,
        //     'password' => bcrypt($request->password)
        // ]);
  
        // $token = $user->createToken('repeps-Auth')->accessToken;
  
        // return response()->json(['token' => $token], 200);

        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
            'c_password' => 'required|same:password',
        ]);
   
        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());       
        }
        
        $input = $request->all();
        $user = User::where('email', '=', $input['email'])->first();
        if (!$user) {                
                $input['password'] = bcrypt($input['password']);
                $user = User::create($input);
                $success['token'] =  $user->createToken('repeps-Auth')->accessToken;
                $success['name'] =  $user->name;
           
                return $this->sendResponse($success, 'User register successfully.');
        }else{
            return $this->sendError('Unauthorised.', ['error'=>'User Already Exists login with different email!']);
        }

        
    }
  
    /**
     * Login Req
     */
    public function login(Request $request)
    {
        // $data = [
        //     'email' => $request->email,
        //     'password' => $request->password
        // ];
  
        // if (auth()->attempt($data)) {
        //     $token = auth()->user()->createToken('repeps-Auth')->accessToken;
        //     return response()->json(['token' => $token], 200);
        // } else {
        //     return response()->json(['error' => 'Unauthorised'], 401);
        // }
        $user = User::where('email', $request->email)->first();

        if ($user) {
            if (Hash::check($request->password, $user->password)) {
                if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
                    $user = Auth::user(); 
                    $success['token'] =  $user->createToken('repeps-Auth')->accessToken; 
                    $success['name'] =  $user->name;
           
                    return $this->sendResponse($success, 'User login successfully.');

                }else{
                    return $this->sendError('Unauthorised.', ['error'=>'Unauthorised']);
                }
            
            } else {
                return $this->sendError('Unauthorised.', ['error'=>'Password mismatch']);
            }
        }else{
                return $this->sendError('Unauthorised.', ['error'=>'User does not exist']);
        }
        
    }
 	
 	/**
     * user Data
     */
    public function userInfo() 
    {
 
     $user = auth()->user();
     if (is_null($user)) {
            return $this->sendError('User not found.');
        }
              
     return response()->json(['user' => $user], 200);
 
    }
}
