// The only reason I’m sharing this is because many people overcomplicate application protection.
// It’s actually very simple to implement effective safeguards.
// This won’t stop experienced attackers, but it helps prevent common threats like DLL patchers and auth swappers.


#include <iostream>
#include <Windows.h>

#include "dependencies/authentucator/auth.h"
#include "dependencies/oxorany/oxorany.h"

using namespace KeyAuth;

std::string name = encrypt ( "your-app" ); // your application username
std::string ownerid = encrypt ( "your-owner-id" ); // your owner id
std::string version = encrypt ( "1.0" ); // app version
std::string url = encrypt ( "https://keyauth.win/api/1.3/" ); // your domain ( can be custom ) 
std::string path = encrypt ( "" ); // ??

api g_auth ( name , ownerid , version , url , path );
api::lockout_state login_guard {};

std::string key;

/*
    Checks whether the user has a specific subscription.
    Used for additional validation beyond successful authentication.
*/

bool check_sub ( std::string sub ) {

    for ( const auto& subscription : g_auth.user_data.subscriptions ) {
        if ( subscription.name == sub ) {
            return true;
        }
    }
    return false;
}

bool lockout_active ( const api::lockout_state& state ) {
    return std::chrono::steady_clock::now ( ) < state.locked_until;
}

int lockout_remaining_ms ( const api::lockout_state& state ) {
    if ( !lockout_active ( state ) )
        return 0;

    return static_cast< int >(
        std::chrono::duration_cast< std::chrono::milliseconds >(
            state.locked_until - std::chrono::steady_clock::now ( ) ).count ( ) );
}

void record_login_fail ( api::lockout_state& state , int max_attempts = 3 , int lock_seconds = 30 ) {
    if ( lockout_active ( state ) )
        return;

    ++state.fails;
    if ( state.fails >= max_attempts ) {
        state.fails = 0;
        state.locked_until = std::chrono::steady_clock::now ( ) + std::chrono::seconds ( lock_seconds );
    }
}

void reset_lockout ( api::lockout_state& state ) {
    state.fails = 0;
    state.locked_until = std::chrono::steady_clock::time_point {};
}

inline void checkAuthenticated ( const std::string& ownerid ) {
    while ( true ) {
        if ( GlobalFindAtomA ( ownerid.c_str ( ) ) == 0 ) {
            exit ( 13 );
        }
        Sleep ( 1000 );
    }
}

void sessionStatus ( ) {
    g_auth.check ( true ); // do NOT specify true usually, it is slower and will get you blocked from API
    if ( !g_auth.response.success ) {
        return; // allow clean exit from thread. -nigel
    }

    if ( g_auth.response.isPaid ) {
        while ( true ) {
            Sleep ( 20000 ); // this MUST be included or else you get blocked from API
            g_auth.check ( );
            if ( !g_auth.response.success ) {
                return; // allow clean exit from thread. -nigel
            }
        }
    }
}

std::string expiry_remaining ( const std::string& expiry ) {
    const std::time_t expiry_time = static_cast< std::time_t >( std::strtoll ( expiry.c_str ( ) , nullptr , 10 ) );
    const std::time_t now = std::time ( nullptr );

    if ( expiry_time <= 0 || expiry_time <= now )
        return "expired";

    long long remaining = static_cast< long long >( expiry_time - now );
    const long long days = remaining / 86400;
    remaining %= 86400;
    const long long hours = remaining / 3600;
    remaining %= 3600;
    const long long minutes = remaining / 60;
    const long long seconds = remaining % 60;

    std::string result;
    if ( days > 0 )
        result += std::to_string ( days ) + "d ";
    if ( days > 0 || hours > 0 )
        result += std::to_string ( hours ) + "h ";
    if ( days > 0 || hours > 0 || minutes > 0 )
        result += std::to_string ( minutes ) + "m ";
    result += std::to_string ( seconds ) + "s";
    return result;
}

std::string tm_to_readable_time ( std::tm ctx ) {
    char buffer [ 80 ];
    strftime ( buffer , sizeof ( buffer ) , "%a %m/%d/%y %H:%M:%S %Z" , &ctx );
    return std::string ( buffer );
}

std::string remaining_until ( const std::string& timestamp ) {
    return expiry_remaining ( timestamp );
}

void print_user_data ( const api& app ) {
    std::cout << encrypt ( "\n User data:" );
    std::cout << encrypt ( "\n Username: " ) << app.user_data.username;
    std::cout << encrypt ( "\n IP address: " ) << app.user_data.ip;
    std::cout << encrypt ( "\n Hardware-Id: " ) << app.user_data.hwid;
    std::cout << encrypt ( "\n Create date: " )
        << tm_to_readable_time ( timestamp_to_tm ( app.user_data.createdate ) );
    std::cout << encrypt ( "\n Last login: " )
        << tm_to_readable_time ( timestamp_to_tm ( app.user_data.lastlogin ) );
    std::cout << encrypt ( "\n Subscription(s): " );

    for ( size_t i = 0; i < app.user_data.subscriptions.size ( ); i++ ) {
        const auto& sub = app.user_data.subscriptions.at ( i );
        std::cout << encrypt ( "\n name: " ) << sub.name;
        std::cout << encrypt ( " : expiry: " )
            << tm_to_readable_time ( timestamp_to_tm ( sub.expiry ) );
        std::cout << encrypt ( " (" ) << remaining_until ( sub.expiry ) << encrypt ( ")" );
    }
}

std::tm timestamp_to_tm ( const std::string& timestamp ) {
    const std::time_t raw = static_cast< std::time_t > ( std::strtoll ( timestamp.c_str ( ) , nullptr , 10 ) );
    std::tm result {};
    localtime_s ( &result , &raw );
    return result;
}

// this version of keyauth 1.3 lib uses GPU For HWID Locking So You Can Replace With The Offical Libary If You Want From Here. https://github.com/KeyAuth/keyauth-cpp-library-1.3API




/*
    Validates that core authentication configuration has not been modified.
    Helps prevent basic string patching or auth swapping attempts.
*/

void validate_auth_integrity ( ) { 

    if ( name != encrypt ( "your-app-name" ) )
        __fastfail ( 0x1 );
    if ( ownerid != encrypt ( "your-owner-id" ) )
        __fastfail ( 0x1 );
    if ( version != encrypt ( "1.0" ) )
        __fastfail ( 0x1 );
}


int main ( )
{

    g_auth.init ( ); // starts auth
    validate_auth_integrity ( );
    const std::string owner_save = ownerid; // preserve for auth check thread.
    name.clear ( ); ownerid.clear ( ); version.clear ( ); url.clear ( ); path.clear ( ); // clears strings inside memory.
    g_auth.enable_secure_strings ( true ); // secures the strings xD


    if ( lockout_active ( login_guard ) ) {
        std::cout << encrypt ( "\n Status: Too many attempts. Try again in " ) << lockout_remaining_ms ( login_guard ) << encrypt ( " ms." );
        Sleep ( 3500 );
        __fastfail ( 0x1 ); // not hookable
        return 0;
    }


    std::cout << encrypt ( "\n Enter license: " );
    std::cin >> key;
    g_auth.license ( key , "" );

    if ( !g_auth.response.success )
    {
        std::cout << ( ( g_auth.response.message.c_str( ) ) );
        g_auth.log ( encrypt ( "user has failed to login" ) );
        record_login_fail ( login_guard );
        SecureZeroMemory ( &key [ 0 ] , key.size ( ) );
        Sleep ( 1500 );
        __fastfail ( 0x1 ); // not hookable
    }

    if ( g_auth.user_data.username != key ) // basically all patchers patch the response instead of the key entered so yeah u can just check the key entered against one on server.
    {
        std::cout << ( encrypt ( "invalid license." ) );
        record_login_fail ( login_guard );
        SecureZeroMemory ( &key [ 0 ] , key.size ( ) );
        Sleep ( 1500 );
        __fastfail ( 0x1 ); // not hookable
    }

    if ( !check_sub ( encrypt ( "your-app-subscription" ) ) ) // fully optional it just helps against dll injection patchers as they set it to default subscription.
    {
        std::cout << ( encrypt ( "invalid subscription." ) );
        record_login_fail ( login_guard );
        SecureZeroMemory ( &key [ 0 ] , key.size ( ) );
        Sleep ( 1500 );
        __fastfail ( 0x1 ); // not hookable
    }

    if ( g_auth.user_data.username.empty ( ) )
        __fastfail ( 0x1 ); // not hookable


    if ( g_auth.response.message.empty ( ) )
        __fastfail ( 0x1 ); // not hookable

    std::thread run ( checkAuthenticated , owner_save );
    // do NOT remove checkAuthenticated(), it MUST stay for security reasons
    std::thread check ( sessionStatus ); // do NOT remove this function either.
    run.detach ( ); // detach immediately to avoid terminate on early exits. -nigel
    check.detach ( ); // detach immediately to avoid terminate on early exits. -nigel



    print_user_data ( g_auth );
    std::cout << encrypt ( "\n\n Status: " ) << g_auth.response.message;
    std::cout << encrypt ( "\n\n Closing in five seconds..." );
    Sleep ( 5000 );
    __fastfail ( 1 );

    return 0;
}
