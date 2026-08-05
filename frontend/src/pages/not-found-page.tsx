import { ArrowLeft, ShieldCheck } from "lucide-react"
import { Link } from "react-router-dom"

import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"

export function NotFoundPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/35 p-4">
      <Card className="w-full max-w-md">
        <CardContent className="flex flex-col items-center px-6 py-8 text-center">
          <div className="flex size-11 items-center justify-center rounded-xl bg-cyan-50 text-cyan-700">
            <ShieldCheck className="size-5" aria-hidden="true" />
          </div>
          <p className="mt-4 text-xs font-medium uppercase tracking-[0.16em] text-cyan-700">
            404
          </p>
          <h1 className="mt-2 font-heading text-xl font-semibold">
            Page not found
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            The requested page does not exist.
          </p>
          <Button asChild className="mt-6">
            <Link to="/sboms">
              <ArrowLeft aria-hidden="true" />
              Back to SBOMs
            </Link>
          </Button>
        </CardContent>
      </Card>
    </main>
  )
}
