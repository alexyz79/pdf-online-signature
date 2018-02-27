/*
  Copyright 2018 Alexandre Pires - c.alexandre.pires@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this 
  software and associated documentation files (the "Software"), to deal in the Software 
  without restriction,  including without  limitation the  rights to use, copy, modify, 
  merge,  publish, distribute,  sublicense, and/or sell  copies of the Software, and to 
  permit persons to whom the Software  is furnished  to do so, subject to the following 
  conditions:

  The above copyright notice and this permission notice shall be included in all copies
  or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF  ANY KIND, EXPRESS OR IMPLIED, 
  INCLUDING  BUT  NOT  LIMITED TO  THE WARRANTIES  OF  MERCHANTABILITY,  FITNESS  FOR A 
  PARTICULAR PURPOSE AND  NONINFRINGEMENT.  IN NO  EVENT SHALL THE AUTHORS OR COPYRIGHT 
  HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
  CONTRACT, TORT OR  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
  OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using PDFOnlineSignature.Models;
using Microsoft.AspNetCore.Authorization;

namespace PDFOnlineSignature.Controllers
{
    public class ReviewersController : Controller
    {
        private readonly PDFOnlineSignatureContext _context;

        private static IEnumerable<SelectListItem> RolesList {
            get {
                return new SelectListItem[] {
                    new SelectListItem() { Text = "Administrator", Value = "Admin" },
                    new SelectListItem() { Text = "Operator", Value = "Operator" },
                    new SelectListItem() { Text = "Reviewer", Value = "Reviewer" }
                };
            }
        }

        public ReviewersController(PDFOnlineSignatureContext context)
        {
            _context = context;
        }

        [Authorize(Policy = "CanAccessOperatorMethods")]    
        public async Task<IActionResult> Index()
        {
            return View(await _context.Reviewer.ToListAsync());
        }

        [Authorize(Policy = "CanAccessOperatorMethods")]    
        public IActionResult Create()
        {
            ViewData["Roles"] = new SelectList(RolesList,"Value","Text");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Uuid,Email,Name,Title,Role")] Reviewer reviewer)
        {
            if (ModelState.IsValid)
            {
                reviewer.Uuid = Guid.NewGuid().ToString();
                _context.Add(reviewer);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }

            return View(reviewer);
        }

        [Authorize(Policy = "CanAccessOperatorMethods")]    
        public async Task<IActionResult> Edit(string uuid)
        {
            if (string.IsNullOrEmpty(uuid))
            {
                return NotFound();
            }

            var reviewer = await _context.Reviewer
                                        .SingleOrDefaultAsync(m => m.Uuid == uuid);
            
            if (reviewer == null)
            {
                return NotFound();
            }
            
            ViewData["Roles"] = new SelectList(RolesList,"Value","Text",reviewer.Role);
            return View(reviewer);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "CanAccessOperatorMethods")]    
        public async Task<IActionResult> Edit(string uuid, [Bind("Uuid,Email,Name,Title,Role")] Reviewer reviewer)
        {
            if (uuid != reviewer.Uuid)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(reviewer);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ReviewerExists(reviewer.Uuid))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(reviewer);
        }

        // GET: Reviewers/Delete/5
        [Authorize(Policy = "CanAccessOperatorMethods")]    
        public async Task<IActionResult> Delete(string uuid)
        {
            if (string.IsNullOrEmpty(uuid))
            {
                return NotFound();
            }

            var reviewer = await _context.Reviewer
                .SingleOrDefaultAsync(m => m.Uuid == uuid);

            if (reviewer == null)
            {
                return NotFound();
            }

            return View(reviewer);
        }

        // POST: Reviewers/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "CanAccessOperatorMethods")]    
        public async Task<IActionResult> DeleteConfirmed(string uuid)
        {
            var reviewer = await _context.Reviewer.SingleOrDefaultAsync(m => m.Uuid == uuid);
            _context.Reviewer.Remove(reviewer);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool ReviewerExists(string uuid)
        {
            return _context.Reviewer.Any(e => e.Uuid == uuid);
        }
    }
}
