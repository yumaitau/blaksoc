/** Plain lessons. An advisory group has not reviewed them. */
export const AWARENESS_LESSONS = [
  {
    id: "bank-change",
    title: "Check the sender before you pay",
    body: "A change of bank details needs a phone call you start.",
  },
  {
    id: "surprise-link",
    title: "Do not trust a surprise link",
    body: "Open the site yourself instead of using the link.",
  },
  {
    id: "own-signin",
    title: "Keep your own sign-in",
    body: "A shared password puts the whole group at risk.",
  },
] as const;

export const AWARENESS_REVIEW = "These lessons have not been reviewed by an advisory group.";
