# Home Assistant

This folder contains the `sky_remote` custom integration for Home Assistant.

## Manual installation

1. Copy `custom_components/sky_remote` into your Home Assistant config directory.
2. Restart Home Assistant.
3. In Home Assistant, go to **Settings → Devices & Services → Add Integration**.
4. Search for **Sky Remote**.
5. Enter the Sky box IP address and, if available, its Wake-on-LAN MAC address.

The integration exposes both a media player entity and a remote entity. The remote entity supports the commands listed in `../Docs/SKY_REMOTE_PROTOCOL.md`.

## Example Lovelace card

```yaml
type: grid
cards:
  - type: heading
    heading: Sky Remote
    heading_style: title
  - type: custom:layout-card
    layout_type: custom:grid-layout
    layout:
      grid-template-columns: 1fr 16px 1fr
      grid-template-areas: |
        "left divider right"
    cards:
      - type: vertical-stack
        view_layout:
          grid-area: left
        cards:
          - type: horizontal-stack
            cards:
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Power
                icon: mdi:power
                name: Power
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Home
                icon: mdi:home
                name: Home
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Search
                icon: mdi:magnify
                name: Search
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Info
                icon: mdi:information
                name: Info
          - type: grid
            columns: 3
            square: true
            cards:
              - type: button
                show_name: false
                show_icon: false
                tap_action:
                  action: none
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: ArrowUp
                icon: mdi:chevron-up
                show_name: false
              - type: button
                show_name: false
                show_icon: false
                tap_action:
                  action: none
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: ArrowLeft
                icon: mdi:chevron-left
                show_name: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Enter
                icon: mdi:circle
                name: OK
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: ArrowRight
                icon: mdi:chevron-right
                show_name: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Backspace
                icon: mdi:arrow-left
                show_name: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: ArrowDown
                icon: mdi:chevron-down
                show_name: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Dismiss
                icon: mdi:close
                show_name: false
          - type: horizontal-stack
            cards:
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: ChannelUp
                icon: mdi:arrow-up-bold
                name: CH+
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: ChannelDown
                icon: mdi:arrow-down-bold
                name: CH-
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: VolumeUp
                icon: mdi:volume-plus
                name: Vol+
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: VolumeDown
                icon: mdi:volume-minus
                name: Vol-
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: VolumeMute
                icon: mdi:volume-off
                name: Mute
          - type: horizontal-stack
            cards:
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: MediaRewind
                icon: mdi:rewind
                name: Rew
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: MediaPlay
                icon: mdi:play-pause
                name: Play
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: MediaFastForward
                icon: mdi:fast-forward
                name: FF
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: MediaRecord
                icon: mdi:record-rec
                name: Rec
      - type: custom:gap-card
      - type: vertical-stack
        view_layout:
          grid-area: right
        card_mod:
          style: |
            ha-card {
              opacity: 0.65;
            }
        cards:
          - type: horizontal-stack
            cards:
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Red
                icon: mdi:square-rounded
                name: Red
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Green
                icon: mdi:square-rounded
                name: Green
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Yellow
                icon: mdi:square-rounded
                name: Yellow
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Blue
                icon: mdi:square-rounded
                name: Blue
          - type: grid
            columns: 3
            square: true
            cards:
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit1
                name: "1"
                show_icon: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit2
                name: "2"
                show_icon: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit3
                name: "3"
                show_icon: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit4
                name: "4"
                show_icon: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit5
                name: "5"
                show_icon: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit6
                name: "6"
                show_icon: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit7
                name: "7"
                show_icon: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit8
                name: "8"
                show_icon: false
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit9
                name: "9"
                show_icon: false
              - type: button
                show_name: false
                show_icon: false
                tap_action:
                  action: none
              - type: button
                tap_action:
                  action: call-service
                  service: remote.send_command
                  target:
                    entity_id: remote.sky_box_remote
                  data:
                    command: Digit0
                name: "0"
                show_icon: false
              - type: button
                show_name: false
                show_icon: false
                tap_action:
                  action: none
```
