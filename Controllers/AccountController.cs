using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ProductManagemet.Models;
using ProductsManagementSystem.Enums;
using ProductsManagementSystem.Models;

namespace ProductsManagementSystem.Controllers
{
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        [HttpGet]
        [Authorize("NotAuthorized")]
        public IActionResult Register()
        {
            return View();
        }


        [HttpPost]
        [Authorize("NotAuthorized")]
        public async Task<IActionResult> Register(Register registerDTO)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Errors = ModelState.Values.SelectMany(t => t.Errors).Select(t => t.ErrorMessage);
                return View(registerDTO);
            }
            var existingUser = await _userManager.FindByEmailAsync(registerDTO.Email);
            ApplicationUser user;

            if (existingUser != null)
            {
                user = existingUser;
                var roleExists = await _userManager.IsInRoleAsync(user, registerDTO.UserType.ToString());

                if (!roleExists)
                {
                    await _userManager.AddToRoleAsync(user, registerDTO.UserType.ToString());
                }
            }
            else
            {
                user = new ApplicationUser
                {
                    Email = registerDTO.Email,
                    UserName = registerDTO.Email,
                    PersonName = registerDTO.PersonName,
                };

                var result = await _userManager.CreateAsync(user, registerDTO.Password);
                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("Register", error.Description);
                    }
                    return View(registerDTO);
                }

                // Assign role to the newly created user
                await _userManager.AddToRoleAsync(user, registerDTO.UserType.ToString());
            }

            // Sign in the user after successful registration
            await _signInManager.SignInAsync(user, isPersistent: false);
            return RedirectToAction(nameof(Index), "Party");
        }

        [HttpGet]
        [Authorize("NotAuthorized")]
        public IActionResult Login()
        {
            return View("Login");
        }

        [HttpPost]
        [Authorize("NotAuthorized")]
        public async Task<IActionResult> Login(Login loginDTO)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.Errors = ModelState.Values.SelectMany(t => t.Errors).Select(t => t.ErrorMessage);
                return View(loginDTO);
            }

            var result = await _signInManager.PasswordSignInAsync(loginDTO.Email, loginDTO.Password, false, false);

            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt. Please check your email and password.");
                return View(loginDTO);
            }

            return RedirectToAction(nameof(Index), "Party");
        }


        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Index), "Party");
        }

    }
}
