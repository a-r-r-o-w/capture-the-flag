#============================================================================#
#============================ARCANE CALCULATOR===============================#
#============================================================================#

import hashlib



# GLOBALS --v
arcane_loop_full = True

username_full = "tron"

star_db_full = {
  "Alpha Centauri": 4.38,
  "Barnard's Star": 5.95,
  "Luhman 16": 6.57,
  "WISE 0855-0714": 7.17,
  "Wolf 359": 7.78,
  "Lalande 21185": 8.29,
  "UV Ceti": 8.58,
  "Sirius": 8.59,
  "Ross 154": 9.69,
  "Yin Sector CL-Y d127": 9.86,
  "Duamta": 9.88,
  "Ross 248": 10.37,
  "WISE 1506+7027": 10.52,
  "Epsilon Eridani": 10.52,
  "Lacaille 9352": 10.69,
  "Ross 128": 10.94,
  "EZ Aquarii": 11.10,
  "61 Cygni": 11.37,
  "Procyon": 11.41,
  "Struve 2398": 11.64,
  "Groombridge 34": 11.73,
  "Epsilon Indi": 11.80,
  "SPF-LF 1": 11.82,
  "Tau Ceti": 11.94,
  "YZ Ceti": 12.07,
  "WISE 0350-5658": 12.09,
  "Luyten's Star": 12.39,
  "Teegarden's Star": 12.43,
  "Kapteyn's Star": 12.76,
  "Talta": 12.83,
  "Lacaille 8760": 12.88
}


def intro_full():
    print("\n===================================================\n")
    print("Welcome to the Arcane Calculator, " + username_full + "!\n")
    print(  "===================================================\n\n")


def menu_full():
    print("___Arcane Calculator___\n\n\
Menu:\n\
(a) Estimate Astral Projection Mana Burn\n\
(b) Estimate Astral Slingshot Approach Vector\n\
(c) Exit Arcane Calculator")

    choice = input("What would you like to do, " \
     + username_full +" (a/b/c)? ")
    
    if choice == "a":
        estimate_burn_full()
    elif choice == "b":
        estimate_vector_full()
    elif choice == "c":
        global arcane_loop_full
        arcane_loop_full = False
        print("Bye!")
    else:
        print("That choice is not valid. Please enter a single, valid "+
         "lowercase letter choice (a/b/c).")


def estimate_burn_full():
  print("\n\nSOL is detected as your nearest star.")
  target_system = input("To which system do you want to travel? ")

  if target_system in star_db_full:
      ly = star_db_full[target_system]
      mana_cost_low = ly**2
      mana_cost_high = ly**3
      print("\n"+ target_system +" will cost between "+ str(mana_cost_low) \
+" and "+ str(mana_cost_high) +" stone(s) to project to\n\n")
  else:
      # TODO : could add option to list known stars
      print("\nStar not found.\n\n")


def estimate_vector_full():
  print("\n\nSOL is detected as your nearest star.")
  print("SAG-A* is deduced as your most highly viable slingshot well.\n")
  print("Error: You must be closer to the galactic center before "+ \
                "calculating a slingshot approach vector.\n\n")


def ui_flow_full():
    intro_full()
    while arcane_loop_full:
        menu_full()

ui_flow_full()

