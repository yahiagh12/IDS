"""UI Helper functions for the IDS GUI.

This module contains reusable UI components and helper functions.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime


def create_labeled_frame(parent, label_text, row, column, columnspan=1):
    """Create and return a labeled frame."""
    frame = ttk.LabelFrame(parent, text=label_text)
    frame.grid(row=row, column=column, columnspan=columnspan, sticky="we", padx=5, pady=5)
    return frame


def create_treeview_with_scrollbar(parent, columns, column_definitions):
    """Create a Treeview with scrollbar and return both widgets."""
    tree = ttk.Treeview(
        parent,
        columns=columns,
        show="headings",
        height=15
    )

    for col, width, heading in column_definitions:
        tree.heading(col, text=heading)
        tree.column(col, width=width, anchor="center")

    scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)

    return tree, scrollbar


def get_finding_color(action):
    """Determine row color based on action.
    
    Returns:
        str: Color name or None
    """
    if action == "Log":
        return "yellow"
    elif action == "Alert":
        return "orange"
    elif action == "Drop Packet":
        return "red"
    else:
        return "lightgreen"


def apply_row_color(tree, item_id, color):
    """Apply color to a tree item."""
    if color and not tree.tag_has(color):
        tree.tag_configure(color, background=color)
    if color:
        tree.item(item_id, tags=(color,))


def show_error(title, message):
    """Show error messagebox."""
    messagebox.showerror(title, message)


def show_warning(title, message):
    """Show warning messagebox."""
    messagebox.showwarning(title, message)


def show_info(title, message):
    """Show info messagebox."""
    messagebox.showinfo(title, message)
