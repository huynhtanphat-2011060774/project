<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Brian2694\Toastr\Facades\Toastr;
use App\Mail\OtpEmail;
use Illuminate\Support\Facades\Mail;
use Hash;
use DB;
use Carbon\Carbon;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;

class RegisterController extends Controller
{
    public function storeUser(Request $request)
{
    $request->validate([
        'name'      => 'required|string|max:255',
        'email'     => 'required|string|email|max:255|unique:users',
        'role_name' => 'required|string|max:255',
        'password'  => [
            'required',
            'string',
            'min:8',
            'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/',
            'confirmed',
        ],
    ]);

    $dt       = Carbon::now();
    $todayDate = $dt->toDayDateTimeString();

    $user = User::create([
        'name'      => $request->name,
        'avatar'    => $request->image,
        'email'     => $request->email,
        'join_date' => $todayDate,
        'role_name' => $request->role_name,
        'status'    => 'Active',
        'password'  => Hash::make($request->password),
    ]);

    // Kiểm tra nếu đăng ký thành công, gửi OTP và chuyển hướng đến trang nhập mã OTP
    if ($user) {
        $this->generateAndSendOTP($user); // Gửi OTP qua email
        return redirect()->route('otp.verify.form')->with('email', $user->email);
    }

    Toastr::success('Create new account successfully :)','Success');
    return redirect('login');
}

function generateAndSendOTP($user) {
    if ($user) {
        $otp = mt_rand(100000, 999999);

        // Gán giá trị OTP cho trường otp của user
        $user->otp = $otp;
        $user->save();

        // Gửi mã OTP qua email
        Mail::to($user->email)->send(new OtpEmail($otp));
    } else {
        // Xử lý trường hợp không có người dùng
        Toastr::error('User not found','Error');
        return redirect()->back();
    }
}

    public function verifyOTP(Request $request) {
        $request->validate([
            'otp' => 'required|string|max:6|min:6',
        ]);

        $user = User::where('email', $request->email)->first();

        if ($user && $user->otp === $request->otp) {
            $user->otp = null;
            $user->save();

            Toastr::success('Registration successful!','Success');
            return redirect('login');
        } else {
            Toastr::error('Invalid OTP','Error');
            return redirect()->back()->with('error', 'Invalid OTP');
        }
    }

    public function showOTPForm()
    {
        return view('auth.passwords.verify_otp');
    }
}
