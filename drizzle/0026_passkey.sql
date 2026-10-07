-- WebAuthn credentials for passkey sign-in (better-auth passkey plugin).
CREATE TABLE IF NOT EXISTS "passkey" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text,
	"public_key" text NOT NULL,
	"user_id" text NOT NULL REFERENCES "user"("id") ON DELETE cascade,
	"credential_id" text NOT NULL,
	"counter" integer NOT NULL,
	"device_type" text NOT NULL,
	"backed_up" boolean NOT NULL,
	"transports" text,
	"aaguid" text,
	"created_at" timestamp with time zone DEFAULT now()
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "passkey_user_idx" ON "passkey" ("user_id");
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "passkey_credential_idx" ON "passkey" ("credential_id");
