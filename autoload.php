<?php
/**
 * Copyright 2014 Daisuke Takahashi<daisuke@extendwings.com>
 *
 * Original Copyright 2014 Facebook, Inc.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

/**
 * You only need this file if you are not using composer.
 * Why are you not using composer?
 * https://getcomposer.org/
 */

/**
 * Register the autoloader for the U2F classes.
 * Based off the official PSR-4 autoloader example found here:
 * https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader-examples.md
 *
 * @param string $class The fully-qualified class name.
 * @return void
 */
spl_autoload_register( function( $class ) {
	// project-specific namespace prefix
	$prefix = 'u2flib_server\\';

	// base directory for the namespace prefix
	$base_dir = defined('U2F_SRC_DIR') ? U2F_SRC_DIR : __DIR__ . '/src/u2flib_server/';

	// does the class use the namespace prefix?
	$len = strlen( $prefix );
	if( strncmp( $prefix, $class, $len ) !== 0) {
		// no, move to the next registered autoloader
		return;
	}

	// get the relative class name
	$relative_class = substr( $class, $len );

	// replace the namespace prefix with the base directory, replace namespace
	// separators with directory separators in the relative class name, append
	// with .php
	$file = $base_dir . str_replace('\\', '/', $relative_class ) . '.php';

	// if the file exists, require it
	if( file_exists( $file ) ) {
		require $file;
	}
});
