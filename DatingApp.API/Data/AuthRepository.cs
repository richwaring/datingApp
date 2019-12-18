using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _context;

        public AuthRepository(DataContext context)
        {
            this._context = context;
        }

        public async Task<User> Login(string username, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.Username == username);

            if( user == null)
                return null;
            
            if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
                return null;

            return user;
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
           //make a new hmac object with the user's salt key in the db....
           using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt)) 
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)); // re-calc the hash for the password using the stored "salt" key

                // compare all the bytes in the byte arrays for the stored password hash, and the recalc'd password hash
                for(int i = 0; i < computedHash.Length; i++) 
                {
                    // if they're different, crap out
                    if(computedHash[i] != passwordHash[i]) return false; 
                }
            } 

            return true; // if we've not found any differences, return true
        }

        public async Task<User> Register(User user, string password)
        {
            
            byte[] passwordHash, PasswordSalt;
            CreatePasswordHash(password, out passwordHash, out PasswordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = PasswordSalt;

            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();
            return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
           using (var hmac = new System.Security.Cryptography.HMACSHA512())
           {
                passwordSalt = hmac.Key; // the randomly generated key created by the HMACSHA512 object
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)); // the hash ecrypted from the password and salt key
           }
        }

        public async Task<bool> UserExists(string username)
        {
            if(await _context.Users.AnyAsync(x => x.Username == username))
            return true;

            return false;
        }
    }
}