/** Office-manager steps. Rendered as text, not as a second wizard. */
export const GUIDE = {
  title: "Put a sensor on each computer",
  lead: "This file does not install itself. You download it, then you or your IT helper run it on the computer.",
  steps: [
    "Pick the place. If that place uses satellite or a slow mobile link, set the link to slow.",
    "Create an installer token for that place. Copy the token if your IT helper asks. This page will not show it again.",
    "Download the file that matches the computer: Windows, Mac, Debian, or Red Hat. Each link lasts 15 minutes.",
    "Windows with Intune: your IT helper adds the Windows file as a script for the staff device group.",
    "Google endpoint management: they push the Mac or Windows file to the computers at that place.",
    "An RMM tool: they run the same file as a script. It joins the group named next to the place.",
    "Come back later. A computer we already see in Microsoft or Google, with no sensor, stays on the task list.",
  ],
  revoke: "If a token gets out, revoke it. Download links for that token stop working.",
  measure: "A slow link is counted from the profile schedule and a full software list. Idle upload has to stay under 20 MB a day. The number above is that count.",
};
