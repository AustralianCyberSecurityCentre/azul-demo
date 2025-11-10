rule ghost_2019_134
{
    meta:
		organisation = "ASD's ACSC"
		id = "acsc_000034"
		rule_group = "implant"
		implant = "ghost"
		rule_version = "1"

	strings:
		$a = { 8A ?? ?? 80 C? 7A 80 F? 19 88 ?? ?? 4? 3B ?? 7? }

		$ = ".?AVCManager@@"
		$ = ".?AVCKernelManager@@"
		$ = ".?AVCFileManager@@"
		$ = ".?AVCShellManager@@"
		$ = ".?AVCSystemManager@@"
		$ = ".?AVCVideoManager@@"
		$ = ".?AVCCameraManager@@"
		$ = ".?AVCAudioManager@@"
		$ = ".?AVCScreenManager@@"
		$ = ".?AVCKeyboardManager@@"
		$ = ".?AVCKeyLoggerManager@@"
		$ = ".?AVCVoiceManager@@"
		$ = ".?AVCClientSocket@@"
		$ = ".?AVCBuffer@@"

	condition:
		uint16(0) == 0x5a4d and ($a or 5 of them)
}