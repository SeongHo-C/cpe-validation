import { useLocation } from "react-router-dom"

export function RouteLocationProbe() {
  const location = useLocation()
  return (
    <output data-testid="route-location" className="sr-only">
      {location.pathname}
      {location.search}
    </output>
  )
}
