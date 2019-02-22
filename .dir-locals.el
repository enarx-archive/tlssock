;;; Emacs configuration for project style
;;;
;;; Emacs doesn't support vim modeline magic, and file-local variables are
;;; either the first line of the file (which vim is already using) or very
;;; verbose at the end of the file.

((nil
  (fill-column . 78)
  (c-basic-offset . 2))
 (c-mode
  (indent-tabs-mode))
 (meson-mode
  (meson-indent-basic . 2))
 (sh-mode
  (sh-basic-offset . 2))
 (yaml-mode
  (yaml-indent-offset . 2)))
