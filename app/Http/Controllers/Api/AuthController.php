<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    //
    public function createUser(Request $request)
    {
        try {
            $validateUser = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users, email',
                'password' => 'required'
            ]);

            //validate
            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateUser->errors(),
                ], 404);
            }

            //validation successful, create user
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);
            return response()->json([
                'status' => true,
                'message' => 'User created successfully',
                'token' => $user->createToken('API TOKEN')->plainTextToken,
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
    public function loginUser(Request $request)
    {
        try {
            //validate data
            $validateUser = Validator::make($request->all(), [
                "email" => "email|required",
                "password" => "required"
            ]);
            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors(),
                ]);
            }

            //check if authentication fails
            if (!Auth::attempt($request->only([
                'email', 'password'
            ]))) {
                return response()->json([
                    'status' => true,
                    'message' => 'authentication failed',
                ], 401);
            }

            //auth successful => get user from db 
            $user = User::where("email", $request->email)->first();

            // return success with authorization token 
            return response()->json([
                'status' => true,
                'message' => 'Logged in successfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken,
            ], 200);
            //
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
}
