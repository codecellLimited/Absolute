@component('mail::message')
# Hello {{$user->name}}

Here is your verification code for Email verification

@component('mail::panel')
<h1 style="font-size: 20px;text-align: center; margin: 0">Your OTP is: {{$user->otp}}</h1>
@endcomponent

Do not share your OTP to anyone. If you need any help, contact with Admin

Thanks,<br>
{{ config('app.name') }}
@endcomponent
