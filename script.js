/**
 * This script handles all page animations and interactions.
 */

document.addEventListener('DOMContentLoaded', () => {

    // --- 1. NAVBAR ACTIVE LINK SCROLLSPY ---
    
    const sections = document.querySelectorAll('section');
    const navLinks = document.querySelectorAll('nav ul li a');

    if (sections.length > 0 && navLinks.length > 0) {
        const navObserverOptions = {
            root: null,
            rootMargin: '0px',
            threshold: 0.6 // 60% of the section must be visible
        };

        const navObserverCallback = (entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const visibleSectionId = entry.target.id;
                    
                    navLinks.forEach(link => {
                        link.classList.remove('active');
                        // Check if link's href matches the section's ID
                        if (link.getAttribute('href') === `#${visibleSectionId}`) {
                            link.classList.add('active');
                        }
                    });
                }
            });
        };

        const navObserver = new IntersectionObserver(navObserverCallback, navObserverOptions);
        
        sections.forEach(section => {
            navObserver.observe(section);
        });
    }

    // --- 2. SCROLL-TRIGGERED FADE-IN ANIMATIONS ---
    
    const animatedElements = document.querySelectorAll('.reveal-on-scroll');

    if (animatedElements.length > 0) {
        const scrollObserverOptions = {
            root: null,
            rootMargin: '0px',
            threshold: 0.15 // Trigger when 15% of the element is visible
        };

        const scrollObserverCallback = (entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    // Add the 'visible' class to trigger the CSS transition
                    entry.target.classList.add('visible');
                    
                    // Stop observing this element once it's visible
                    observer.unobserve(entry.target);
                }
            });
        };

        const scrollObserver = new IntersectionObserver(scrollObserverCallback, scrollObserverOptions);

        animatedElements.forEach(el => {
            scrollObserver.observe(el);
        });
    }

});