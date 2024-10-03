<?php

namespace YourVendor\SecurityDetector;

use Illuminate\Support\ServiceProvider;

class SecurityDetectorServiceProvider extends ServiceProvider
{
    public function boot()
    {
        // Register middleware
        $this->app['router']->pushMiddlewareToGroup('web', \YourVendor\SecurityDetector\Http\Middleware\DetectInjectionMiddleware::class);
    }

    public function register()
    {
        // Register any bindings if necessary
    }
}
