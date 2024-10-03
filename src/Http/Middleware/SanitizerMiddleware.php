<?php

namespace YourVendor\SecurityDetector\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class DetectInjectionMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $input = $request->all();
        $pythonScriptPath = base_path('packages/YourVendor/SecurityDetector/src/Python/security_detector.py');

        foreach ($input as $key => $value) {
            if ($request->hasFile($key)) {
                $file = $request->file($key);
                $filePath = $file->getPathname();

                $command = "python3 $pythonScriptPath \"$filePath\"";
                $result = shell_exec($command);

                if (strpos($result, "Potential injection detected!") !== false || strpos($result, "Potential executable file detected!") !== false) {
                    return response()->json(['error' => 'Potential security threat detected!'], 403);
                }
            } else {
                $command = "python3 $pythonScriptPath \"$value\"";
                $result = shell_exec($command);

                if (strpos($result, "Potential injection detected!") !== false) {
                    return response()->json(['error' => 'Potential security threat detected!'], 403);
                }
            }
        }

        return $next($request);
    }
}
