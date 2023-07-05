using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace LoginMSFT.Controllers
{
    public class UserLoginController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public UserLoginController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? message= null)
        {
            if (message != null)
            {
                ViewData["Message"] = message;
            }
            return View();
        }

        [AllowAnonymous]
        [HttpGet]
        public ChallengeResult ExternalLogin(string provider, string? returnUrl = null)
        {
            var urlRedirection = Url.Action("ExternalUserRegister", values: new {returnUrl});
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, urlRedirection);

            return new ChallengeResult(provider,properties);       
        }


        [AllowAnonymous]
        public async Task<IActionResult> ExternalUserRegister(string? returnUrl = null,
                                                               string? remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            var message = "";

            if (remoteError != null)
            {
                message = $"Error from external provider: {remoteError}";
                return RedirectToAction("login", routeValues: new { message });
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                message = "Erro laoding external login information.";
                return RedirectToAction("login", routeValues: new { message });
            }

            var ExternalLoginResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);


            // Ya la cuenta existe
            if (ExternalLoginResult.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }

            string email = "";

            if(info.Principal.HasClaim(c=>c.Type == ClaimTypes.Email))
            {
                email = info.Principal.FindFirstValue(ClaimTypes.Email)!;
            }
            else
            {
                message = "Error with the clients email";
                return RedirectToAction("login",routeValues: new { message });
            }

            var user = new IdentityUser() { Email = email, UserName = email };

            var createUserResult = await _userManager.CreateAsync(user);
            if(!createUserResult.Succeeded)
            {
                message = createUserResult.Errors.First().Description;
                return RedirectToAction("login", routeValues: new { message });
            }

            var addLoginResult = await _userManager.AddLoginAsync(user, info);

            if (!addLoginResult.Succeeded)
            {
                await _signInManager.SignInAsync(user,isPersistent: false, info.LoginProvider);
                return LocalRedirect(returnUrl);
            }
            message = " Error with the login";
            return RedirectToAction("login", new { message }); 
        }

        [HttpPost]
        public async Task<IActionResult> loguout()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return RedirectToAction("Idenx", "Home");
        }
    }
}
