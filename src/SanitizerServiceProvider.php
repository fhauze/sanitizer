<?php

namespace Fir2be\Sanitizer;

use Illuminate\Support\ServiceProvider;

class SanitizerServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        // Publikasi file middleware jika diperlukan, contoh:
        $this->publishes([
            __DIR__ . '/Http/Middleware/SanitizerMiddleware.php' => base_path('app/Http/Middleware/SanitizerMiddleware.php'),
        ], 'sanitizer-middleware');
    }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        // Register Middleware secara manual jika diperlukan
        $this->app['router']->aliasMiddleware('sanitizer', \Fir2be\Sanitizer\Http\Middleware\SanitizerMiddleware::class);
    }
}
