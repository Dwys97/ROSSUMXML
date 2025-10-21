import React, { useEffect, useRef, useCallback } from 'react';
import PropTypes from 'prop-types';
import styles from './BaseModal.module.css';

/**
 * BaseModal - Unified modal component with consistent styling and accessibility
 * 
 * @param {boolean} isOpen - Controls modal visibility
 * @param {function} onClose - Callback when modal should close
 * @param {string} title - Modal title (rendered in header)
 * @param {string} subtitle - Optional subtitle below title
 * @param {ReactNode} header - Custom header content (overrides title/subtitle)
 * @param {ReactNode} headerSlot - Additional content after title (e.g., tabs)
 * @param {ReactNode} footer - Optional footer content
 * @param {ReactNode} children - Modal content
 * @param {string} size - Modal size: 'small' (500px), 'medium' (900px), 'large' (1200px), 'xl' (1400px)
 * @param {string} className - Additional CSS classes for modal container
 * @param {string} contentClassName - Additional CSS classes for content area
 * @param {boolean} closeOnOverlayClick - Allow closing by clicking overlay (default: true)
 * @param {boolean} closeOnEscape - Allow closing with ESC key (default: true)
 * @param {boolean} showCloseButton - Show close button in header (default: true)
 * @param {string} ariaLabel - Accessible label for modal
 */
const BaseModal = ({
  isOpen,
  onClose,
  title,
  subtitle,
  header,
  headerSlot,
  footer,
  children,
  size = 'large',
  className = '',
  contentClassName = '',
  closeOnOverlayClick = true,
  closeOnEscape = true,
  showCloseButton = true,
  ariaLabel,
}) => {
  const modalRef = useRef(null);
  const previousFocusRef = useRef(null);
  const closeButtonRef = useRef(null);

  // Handle ESC key press
  const handleEscapeKey = useCallback(
    (event) => {
      if (closeOnEscape && event.key === 'Escape' && isOpen) {
        onClose();
      }
    },
    [closeOnEscape, isOpen, onClose]
  );

  // Handle overlay click
  const handleOverlayClick = useCallback(
    (event) => {
      if (closeOnOverlayClick && event.target === event.currentTarget) {
        onClose();
      }
    },
    [closeOnOverlayClick, onClose]
  );

  // Focus management
  useEffect(() => {
    if (isOpen) {
      // Store current focus
      previousFocusRef.current = document.activeElement;

      // Focus close button or first focusable element
      setTimeout(() => {
        if (closeButtonRef.current) {
          closeButtonRef.current.focus();
        } else {
          const firstFocusable = modalRef.current?.querySelector(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          );
          firstFocusable?.focus();
        }
      }, 100);

      // Lock body scroll
      document.body.style.overflow = 'hidden';
    } else {
      // Restore body scroll
      document.body.style.overflow = '';

      // Restore previous focus
      if (previousFocusRef.current) {
        previousFocusRef.current.focus();
      }
    }

    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  // ESC key listener
  useEffect(() => {
    document.addEventListener('keydown', handleEscapeKey);
    return () => {
      document.removeEventListener('keydown', handleEscapeKey);
    };
  }, [handleEscapeKey]);

  // Focus trap
  useEffect(() => {
    if (!isOpen || !modalRef.current) return;

    const modal = modalRef.current;
    const focusableElements = modal.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    const handleTabKey = (e) => {
      if (e.key !== 'Tab') return;

      if (e.shiftKey) {
        // Shift + Tab
        if (document.activeElement === firstElement) {
          e.preventDefault();
          lastElement?.focus();
        }
      } else {
        // Tab
        if (document.activeElement === lastElement) {
          e.preventDefault();
          firstElement?.focus();
        }
      }
    };

    modal.addEventListener('keydown', handleTabKey);
    return () => {
      modal.removeEventListener('keydown', handleTabKey);
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const sizeClass = styles[`modal${size.charAt(0).toUpperCase() + size.slice(1)}`];

  return (
    <div
      className={styles.overlay}
      onClick={handleOverlayClick}
      role="presentation"
    >
      <div
        ref={modalRef}
        className={`${styles.modal} ${sizeClass} ${className}`}
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabel || title}
      >
        {/* Close Button */}
        {showCloseButton && (
          <button
            ref={closeButtonRef}
            className={styles.closeButton}
            onClick={onClose}
            aria-label="Close modal"
            type="button"
          >
            ×
          </button>
        )}

        {/* Header */}
        {(header || title) && (
          <header className={styles.header}>
            {header || (
              <div className={styles.headerContent}>
                <h1 className={styles.title}>{title}</h1>
                {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
              </div>
            )}
          </header>
        )}

        {/* Header Slot (e.g., tabs) */}
        {headerSlot && <div className={styles.headerSlot}>{headerSlot}</div>}

        {/* Content */}
        <div className={`${styles.content} ${contentClassName}`}>
          {children}
        </div>

        {/* Footer */}
        {footer && <footer className={styles.footer}>{footer}</footer>}
      </div>
    </div>
  );
};

BaseModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  title: PropTypes.string,
  subtitle: PropTypes.string,
  header: PropTypes.node,
  headerSlot: PropTypes.node,
  footer: PropTypes.node,
  children: PropTypes.node.isRequired,
  size: PropTypes.oneOf(['small', 'medium', 'large', 'xl']),
  className: PropTypes.string,
  contentClassName: PropTypes.string,
  closeOnOverlayClick: PropTypes.bool,
  closeOnEscape: PropTypes.bool,
  showCloseButton: PropTypes.bool,
  ariaLabel: PropTypes.string,
};

export default BaseModal;
