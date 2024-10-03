<?php

namespace Fir2be\Sanitizer\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SanitizerMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Cek semua input dari request
        $input = $request->all();

        // Tentukan path ke skrip Python
        $pythonScriptPath = base_path('vendor/fir2be/sanitizer/src/Python/Sanitizer.py');

        // Cek setiap input
        foreach ($input as $key => $value) {
            // Jika input adalah file
            if ($request->hasFile($key)) {
                $file = $request->file($key);
                $filePath = $file->getPathname();

                // Jalankan program Python untuk memeriksa file
                $command = escapeshellcmd("python3 $pythonScriptPath file \"$filePath\"");
                $result = shell_exec($command);

                // Jika terdeteksi file executable, kembalikan respons error
                if (strpos($result, "Potential executable file detected!") !== false) {
                    return response()->json(['error' => 'Executable file detected!'], 403);
                }
            } else {
                // Jalankan program Python untuk input string
                $command = escapeshellcmd("python3 $pythonScriptPath string \"$value\"");
                $result = shell_exec($command);

                // Jika terdeteksi injeksi, kembalikan respons error
                if (strpos($result, "Potential injection detected!") !== false) {
                    return response()->json(['error' => 'Potential security threat detected!'], 403);
                }
            }
        }

        return $next($request);
    }
}
